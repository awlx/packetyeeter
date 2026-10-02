package collector

import (
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"PacketYeeter/pkg/collector/ebpf"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

func TestValidateModeConfig(t *testing.T) {
	scrub := Config{Mode: ebpf.ModeScrub, Interface: "eth0", InsideInterface: "eth1", XDPMode: ebpf.XDPModeAuto}
	host := func(c *Config) { c.Mode = ebpf.ModeHost; c.InsideInterface = "" }
	for name, tc := range map[string]struct {
		mutate   func(*Config)
		ok       bool
		warnings int
	}{
		"host": {host, true, 0},
		"host with default drain": {func(c *Config) {
			host(c)
			c.ReadyzDrain = DefaultReadyzDrain
			c.ScrubSlowPathPPS = DefaultScrubSlowPathPPS
		}, true, 0},
		"host with custom drain":    {func(c *Config) { host(c); c.ReadyzDrain = time.Second }, true, 1},
		"host with custom slow pps": {func(c *Config) { host(c); c.ScrubSlowPathPPS = 5 }, true, 1},
		"host with inside-if":       {func(c *Config) { host(c); c.InsideInterface = "eth1" }, false, 0},
		"host with allow-generic":   {func(c *Config) { host(c); c.AllowGeneric = true }, false, 0},
		"scrub":                     {func(*Config) {}, true, 0},
		"missing inside":            {func(c *Config) { c.InsideInterface = "" }, false, 0},
		"inside equals outside":     {func(c *Config) { c.InsideInterface = "eth0" }, false, 0},
		"generic not allowed":       {func(c *Config) { c.XDPMode = ebpf.XDPModeGeneric }, false, 0},
		"generic allowed":           {func(c *Config) { c.XDPMode = ebpf.XDPModeGeneric; c.AllowGeneric = true }, true, 0},
		"egress accounting":         {func(c *Config) { c.EgressAccounting = true }, false, 0},
	} {
		cfg := scrub
		tc.mutate(&cfg)
		warnings, err := validateModeConfig(cfg)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
		if len(warnings) != tc.warnings {
			t.Errorf("%s: warnings = %q, want %d", name, warnings, tc.warnings)
		}
	}
}

func fakeSysctls(values map[string]string) sysctlReader {
	return func(name string) (string, error) {
		v, ok := values[name]
		if !ok {
			return "", errors.New("no such sysctl")
		}
		return v, nil
	}
}

func TestCheckScrubSysctls(t *testing.T) {
	base := map[string]string{
		"net/ipv4/ip_forward":               "1",
		"net/ipv4/conf/eth0.100/forwarding": "1",
		"net/ipv6/conf/all/forwarding":      "1",
		"net/ipv6/conf/eth0.100/forwarding": "1",
		"net/ipv4/conf/all/rp_filter":       "0",
		"net/ipv4/conf/eth0.100/rp_filter":  "2",
	}
	for name, tc := range map[string]struct {
		set  map[string]string
		ipv6 bool
		ok   bool
	}{
		"ok":                       {nil, true, true},
		"ipv4 forwarding off":      {map[string]string{"net/ipv4/ip_forward": "0"}, false, false},
		"ipv4 port forwarding off": {map[string]string{"net/ipv4/conf/eth0.100/forwarding": "0"}, false, false},
		"ipv6 forwarding off":      {map[string]string{"net/ipv6/conf/all/forwarding": "0"}, true, false},
		"ipv6 port forwarding off": {map[string]string{"net/ipv6/conf/eth0.100/forwarding": "0"}, true, false},
		"ipv6 unused":              {map[string]string{"net/ipv6/conf/all/forwarding": "0"}, false, true},
		"strict all":               {map[string]string{"net/ipv4/conf/all/rp_filter": "1", "net/ipv4/conf/eth0.100/rp_filter": "0"}, true, false},
		"strict port":              {map[string]string{"net/ipv4/conf/eth0.100/rp_filter": "1"}, true, false},
		"loose all, strict port":   {map[string]string{"net/ipv4/conf/all/rp_filter": "2", "net/ipv4/conf/eth0.100/rp_filter": "1"}, true, true},
	} {
		values := map[string]string{}
		for k, v := range base {
			values[k] = v
		}
		for k, v := range tc.set {
			values[k] = v
		}
		if err := checkScrubSysctls(fakeSysctls(values), "eth0.100", tc.ipv6); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

func TestNeedIPv6Forwarding(t *testing.T) {
	cidr := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	linkLocalOnly := map[string][]net.IP{
		"eth0": {net.ParseIP("192.0.2.1"), net.ParseIP("fe80::1")},
		"eth1": {net.ParseIP("10.0.0.1"), net.ParseIP("fe80::2")},
	}
	kernelRoutes := []*net.IPNet{cidr("fe80::/64"), cidr("ff00::/8")}
	for name, tc := range map[string]struct {
		addrs  map[string][]net.IP
		routes []*net.IPNet
		want   bool
	}{
		"ipv4 only":                 {linkLocalOnly, kernelRoutes, false},
		"no routes":                 {linkLocalOnly, nil, false},
		"global on outside":         {map[string][]net.IP{"eth0": {net.ParseIP("2001:db8::1")}, "eth1": nil}, nil, true},
		"global on inside":          {map[string][]net.IP{"eth0": nil, "eth1": {net.ParseIP("2001:db8:1::1")}}, nil, true},
		"link-local next hop route": {linkLocalOnly, append(kernelRoutes, cidr("2001:db8:100::/48")), true},
		"default route (nil dst)":   {linkLocalOnly, append(kernelRoutes, nil), true},
		"default route (::/0)":      {linkLocalOnly, append(kernelRoutes, cidr("::/0")), true},
	} {
		env := ipv6Env{
			addrs: func(iface string) ([]net.IP, error) { return tc.addrs[iface], nil },
			routeDsts: func(iface string) ([]*net.IPNet, error) {
				if iface != "eth1" {
					t.Errorf("%s: routes looked up on %s, want the inside port", name, iface)
				}
				return tc.routes, nil
			},
		}
		got, err := needIPv6Forwarding(env, "eth0", "eth1")
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", name, got, err, tc.want)
		}
	}

	failing := ipv6Env{
		addrs:     func(string) ([]net.IP, error) { return nil, nil },
		routeDsts: func(string) ([]*net.IPNet, error) { return nil, errors.New("netlink down") },
	}
	if _, err := needIPv6Forwarding(failing, "eth0", "eth1"); err == nil {
		t.Error("route lookup failure was not reported")
	}
}

func TestReportLocalAddrsSync(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	c := &Collector{Logger: logger}
	full := errors.New("local_addrs full")
	for _, err := range []error{nil, full, full, full, nil, nil} {
		c.reportLocalAddrsSync(err)
	}
	if got := len(hook.AllEntries()); got != 2 {
		t.Fatalf("logged %d entries, want 2 (failure once, recovery once)", got)
	}
}

func TestScrubReadyz(t *testing.T) {
	failing := errors.New("eth1 is down")
	c := &Collector{readinessChecks: []readinessCheck{
		{"xdp_scrub", func() error { return nil }},
		{"inside port", func() error { return failing }},
	}}

	rec := httptest.NewRecorder()
	readyzHandler(c.scrubReady)(rec, httptest.NewRequest("GET", "/readyz", nil))
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != 503 || !strings.Contains(string(body), "inside port: eth1 is down") {
		t.Fatalf("got %d %q, want 503 naming the failed check", rec.Code, body)
	}

	c.readinessChecks[1].check = func() error { return nil }
	rec = httptest.NewRecorder()
	readyzHandler(c.scrubReady)(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}

	c.draining.Store(true)
	if err := c.scrubReady(); err == nil || !strings.Contains(err.Error(), "draining") {
		t.Fatalf("scrubReady while draining = %v", err)
	}
}

func TestScrubMetrics(t *testing.T) {
	var st ebpf.ScrubStats
	st.Verdicts[0][0] = ebpf.ScrubCounter{Packets: 7, Bytes: 700} // forward/ipv4
	st.SlowPath[ebpf.ScrubSlowTTL] = 3
	st.SlowLimited = 9
	m := &scrubMetrics{
		stats:  func() (ebpf.ScrubStats, error) { return st, nil },
		ready:  func() error { return nil },
		logger: logrus.New(),
	}
	want := `
# HELP packetyeeter_scrub_ready 1 when /readyz reports the scrub node ready, else 0
# TYPE packetyeeter_scrub_ready gauge
packetyeeter_scrub_ready 1
# HELP packetyeeter_scrub_slow_path_limited_total Slow-path packets over -scrub-slow-path-pps, dropped (or passed in monitor mode)
# TYPE packetyeeter_scrub_slow_path_limited_total counter
packetyeeter_scrub_slow_path_limited_total 9
# HELP packetyeeter_scrub_ttl_expired_total Packets arriving with TTL/hop limit <= 1; a rising rate indicates a routing loop
# TYPE packetyeeter_scrub_ttl_expired_total counter
packetyeeter_scrub_ttl_expired_total 3
`
	if err := testutil.CollectAndCompare(m, strings.NewReader(want), "packetyeeter_scrub_ready", "packetyeeter_scrub_slow_path_limited_total", "packetyeeter_scrub_ttl_expired_total"); err != nil {
		t.Error(err)
	}
	if got := testutil.CollectAndCount(m, "packetyeeter_scrub_packets_total"); got != 12 {
		t.Errorf("scrub_packets_total series = %d, want 12 (4 verdicts x 3 families)", got)
	}
	if got := testutil.CollectAndCount(m, "packetyeeter_scrub_slow_path_total"); got != len(ebpf.ScrubSlowReasonNames) {
		t.Errorf("scrub_slow_path_total series = %d, want %d", got, len(ebpf.ScrubSlowReasonNames))
	}
}
