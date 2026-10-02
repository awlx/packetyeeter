package collector

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"PacketYeeter/pkg/collector/ebpf"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

func TestValidateModeConfig(t *testing.T) {
	scrub := Config{Mode: ebpf.ModeScrub, Interface: "eth0", InsideInterface: "eth1", XDPMode: ebpf.XDPModeAuto}
	for name, tc := range map[string]struct {
		mutate func(*Config)
		ok     bool
	}{
		"host ignores scrub flags": {func(c *Config) { c.Mode = ebpf.ModeHost; c.InsideInterface = "" }, true},
		"scrub":                    {func(*Config) {}, true},
		"missing inside":           {func(c *Config) { c.InsideInterface = "" }, false},
		"inside equals outside":    {func(c *Config) { c.InsideInterface = "eth0" }, false},
		"generic not allowed":      {func(c *Config) { c.XDPMode = ebpf.XDPModeGeneric }, false},
		"generic allowed":          {func(c *Config) { c.XDPMode = ebpf.XDPModeGeneric; c.AllowGeneric = true }, true},
		"egress accounting":        {func(c *Config) { c.EgressAccounting = true }, false},
	} {
		cfg := scrub
		tc.mutate(&cfg)
		if err := validateModeConfig(cfg); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
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
		"net/ipv4/ip_forward":              "1",
		"net/ipv6/conf/all/forwarding":     "1",
		"net/ipv4/conf/all/rp_filter":      "0",
		"net/ipv4/conf/eth0/100/rp_filter": "2",
	}
	for name, tc := range map[string]struct {
		set  map[string]string
		ipv6 bool
		ok   bool
	}{
		"ok":                     {nil, true, true},
		"ipv4 forwarding off":    {map[string]string{"net/ipv4/ip_forward": "0"}, false, false},
		"ipv6 forwarding off":    {map[string]string{"net/ipv6/conf/all/forwarding": "0"}, true, false},
		"ipv6 unused":            {map[string]string{"net/ipv6/conf/all/forwarding": "0"}, false, true},
		"strict all":             {map[string]string{"net/ipv4/conf/all/rp_filter": "1", "net/ipv4/conf/eth0/100/rp_filter": "0"}, true, false},
		"strict port":            {map[string]string{"net/ipv4/conf/eth0/100/rp_filter": "1"}, true, false},
		"loose all, strict port": {map[string]string{"net/ipv4/conf/all/rp_filter": "2", "net/ipv4/conf/eth0/100/rp_filter": "1"}, true, true},
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
	m := &scrubMetrics{
		stats:  func() (ebpf.ScrubStats, error) { return st, nil },
		ready:  func() error { return nil },
		logger: logrus.New(),
	}
	want := `
# HELP packetyeeter_scrub_ready 1 when /readyz reports the scrub node ready, else 0
# TYPE packetyeeter_scrub_ready gauge
packetyeeter_scrub_ready 1
# HELP packetyeeter_scrub_ttl_expired_total Packets arriving with TTL/hop limit <= 1; a rising rate indicates a routing loop
# TYPE packetyeeter_scrub_ttl_expired_total counter
packetyeeter_scrub_ttl_expired_total 3
`
	if err := testutil.CollectAndCompare(m, strings.NewReader(want), "packetyeeter_scrub_ready", "packetyeeter_scrub_ttl_expired_total"); err != nil {
		t.Error(err)
	}
	if got := testutil.CollectAndCount(m, "packetyeeter_scrub_packets_total"); got != 12 {
		t.Errorf("scrub_packets_total series = %d, want 12 (4 verdicts x 3 families)", got)
	}
}
