package collector

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Defaults of the scrub-only flags, so host mode can warn when they are set.
const (
	DefaultReadyzDrain      = 5 * time.Second
	DefaultScrubSlowPathPPS = 100000
)

// validateModeConfig rejects flag combinations that would otherwise be
// silently ignored. Settings that are harmless but unused yield warnings.
func validateModeConfig(cfg Config) (warnings []string, err error) {
	if cfg.Mode != ebpf.ModeScrub {
		switch {
		case cfg.InsideInterface != "":
			return nil, errors.New("-inside-if is only valid with -mode scrub")
		case cfg.AllowGeneric:
			return nil, errors.New("-allow-generic is only valid with -mode scrub")
		}
		if cfg.ReadyzDrain != 0 && cfg.ReadyzDrain != DefaultReadyzDrain {
			warnings = append(warnings, "-readyz-drain has no effect in host mode")
		}
		if cfg.ScrubSlowPathPPS != 0 && cfg.ScrubSlowPathPPS != DefaultScrubSlowPathPPS {
			warnings = append(warnings, "-scrub-slow-path-pps has no effect in host mode")
		}
		return warnings, nil
	}
	return nil, validateScrubConfig(cfg)
}

func validateScrubConfig(cfg Config) error {
	switch {
	case cfg.InsideInterface == "":
		return errors.New("scrub mode requires -inside-if")
	case cfg.InsideInterface == cfg.Interface:
		return errors.New("-inside-if must differ from -i (the outside port)")
	case cfg.XDPMode == ebpf.XDPModeGeneric && !cfg.AllowGeneric:
		return errors.New("-xdp-mode generic in scrub mode requires -allow-generic")
	case cfg.EgressAccounting:
		return errors.New("-egress-accounting is not available in scrub mode (no TC programs)")
	}
	return nil
}

type sysctlReader func(name string) (string, error)

func procSysctl(name string) (string, error) {
	b, err := os.ReadFile("/proc/sys/" + name)
	return strings.TrimSpace(string(b)), err
}

func readSysctlInt(read sysctlReader, name string) (int, error) {
	v, err := read(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(v)
}

// checkForwarding requires kernel forwarding because the slow path and the
// fail-open behaviour (collector stopped or crashed) both rely on the kernel
// forwarding redirected traffic. bpf_fib_lookup checks the ingress (outside)
// port's setting, the kernel's IPv6 forwarding path the global one.
//
// procfs keeps dots in interface names (conf/eth0.100); only sysctl(8) key
// notation rewrites them to slashes.
func checkForwarding(read sysctlReader, outside string, ipv6 bool) error {
	names := []string{"net/ipv4/ip_forward", "net/ipv4/conf/" + outside + "/forwarding"}
	if ipv6 {
		names = append(names, "net/ipv6/conf/all/forwarding", "net/ipv6/conf/"+outside+"/forwarding")
	}
	for _, name := range names {
		v, err := readSysctlInt(read, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if v != 1 {
			return fmt.Errorf("/proc/sys/%s must be 1, is %d", name, v)
		}
	}
	return nil
}

// checkScrubSysctls also rejects strict reverse-path filtering on the outside
// port: attack sources are spoofed, so it would drop slow-path packets.
func checkScrubSysctls(read sysctlReader, outside string, ipv6 bool) error {
	if err := checkForwarding(read, outside, ipv6); err != nil {
		return err
	}
	all, err := readSysctlInt(read, "net/ipv4/conf/all/rp_filter")
	if err != nil {
		return fmt.Errorf("read rp_filter: %w", err)
	}
	port, err := readSysctlInt(read, "net/ipv4/conf/"+outside+"/rp_filter")
	if err != nil {
		return fmt.Errorf("read rp_filter for %s: %w", outside, err)
	}
	// The kernel applies the larger of the two values.
	if max(all, port) == 1 {
		return fmt.Errorf("strict rp_filter on %s: set /proc/sys/net/ipv4/conf/{all,%s}/rp_filter to 0 or 2", outside, outside)
	}
	return nil
}

// ipv6Env abstracts the interface and route lookups needIPv6Forwarding uses.
type ipv6Env struct {
	addrs func(iface string) ([]net.IP, error)
	// routeDsts lists the destinations of the IPv6 routes leaving through
	// iface; nil stands for a default route.
	routeDsts func(iface string) ([]*net.IPNet, error)
}

var systemIPv6Env = ipv6Env{addrs: interfaceIPs, routeDsts: ipv6RouteDsts}

func interfaceIPs(name string) ([]net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			ips = append(ips, ipn.IP)
		}
	}
	return ips, nil
}

// needIPv6Forwarding decides whether IPv6 forwarding is required: whenever the
// node can route IPv6 out of the inside port (link-local next hops leave no
// global address on either port) or has a global IPv6 address on either port.
// Without forwarding, bpf_fib_lookup returns NOT_FWDED and the kernel drops
// the transit traffic. Turning it on unconditionally would stop SLAAC on
// management interfaces of IPv4-only nodes.
func needIPv6Forwarding(env ipv6Env, outside, inside string) (bool, error) {
	for _, name := range []string{outside, inside} {
		ips, err := env.addrs(name)
		if err != nil {
			return false, fmt.Errorf("list addresses of %s: %w", name, err)
		}
		for _, ip := range ips {
			if ip.To4() == nil && ip.IsGlobalUnicast() {
				return true, nil
			}
		}
	}
	dsts, err := env.routeDsts(inside)
	if err != nil {
		return false, fmt.Errorf("list IPv6 routes via %s: %w", inside, err)
	}
	for _, dst := range dsts {
		if dst == nil || dst.IP.IsUnspecified() {
			return true, nil
		}
		if !dst.IP.IsLinkLocalUnicast() && !dst.IP.IsMulticast() {
			return true, nil
		}
	}
	return false, nil
}

// checkForwardingSysctls only works out whether IPv6 forwarding is needed when
// it is off: /readyz and every scrape run this, and the route dump can be a
// full BGP table.
func (c *Collector) checkForwardingSysctls(check func(ipv6 bool) error) error {
	if check(true) == nil {
		return nil
	}
	ipv6, err := needIPv6Forwarding(systemIPv6Env, c.Config.Interface, c.Config.InsideInterface)
	if err != nil {
		return err
	}
	return check(ipv6)
}

func (c *Collector) preflightScrub() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	if err := ebpf.CheckKernelRelease(unix.ByteSliceToString(uts.Release[:]), ebpf.ScrubMinKernel); err != nil {
		return err
	}
	return c.checkForwardingSysctls(func(ipv6 bool) error {
		return checkScrubSysctls(procSysctl, c.Config.Interface, ipv6)
	})
}

func checkInsidePort(name string, inTxPorts func(ifindex int) (bool, error)) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("%s is down", name)
	}
	if iface.Flags&net.FlagRunning == 0 {
		return fmt.Errorf("%s has no carrier", name)
	}
	ok, err := inTxPorts(iface.Index)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s (ifindex %d) is not in tx_ports", name, iface.Index)
	}
	return nil
}

type readinessCheck struct {
	name  string
	check func() error
}

func (c *Collector) scrubReadinessChecks() []readinessCheck {
	return []readinessCheck{
		{"xdp_scrub", c.Loader.ScrubAttached},
		{"inside port", func() error { return checkInsidePort(c.Config.InsideInterface, c.Maps.HasTxPort) }},
		{"forwarding", func() error {
			return c.checkForwardingSysctls(func(ipv6 bool) error {
				return checkForwarding(procSysctl, c.Config.Interface, ipv6)
			})
		}},
	}
}

func (c *Collector) scrubReady() error {
	if c.draining.Load() {
		return errors.New("draining for shutdown")
	}
	for _, rc := range c.readinessChecks {
		if err := rc.check(); err != nil {
			return fmt.Errorf("%s: %w", rc.name, err)
		}
	}
	return nil
}

func readyzHandler(ready func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if err := ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "not ready: %v\n", err)
			return
		}
		fmt.Fprintln(w, "ready")
	}
}

// syncLocalAddrs is polled rather than driven by netlink events: until a new
// address lands in local_addrs, the FIB lookup already hands its traffic to
// the kernel (counted as slow_path{reason="not_fwded"}); the map only limits
// it to the policy and blocklist checks.
func (c *Collector) syncLocalAddrs() error {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("list local addresses: %w", err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			ips = append(ips, ipn.IP)
		}
	}
	return c.Maps.SyncLocalAddrs(ips)
}

// reportLocalAddrsSync logs a poll-time sync failure only when it changes, and
// once on recovery, so a persistent problem does not log on every poll.
func (c *Collector) reportLocalAddrsSync(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg == c.lastLocalAddrsErr {
		return
	}
	if err != nil {
		c.Logger.WithError(err).Warn("Failed to sync local_addrs")
	} else {
		c.Logger.Info("local_addrs sync recovered")
	}
	c.lastLocalAddrsErr = msg
}

// scrubMetrics reads the kernel counters at scrape time, so the exported
// counters are exact rather than sampled by a poll loop.
type scrubMetrics struct {
	stats       func() (ebpf.ScrubStats, error)
	ready       func() error
	ruleMatches func() (map[uint8]uint64, error)
	ruleCounts  func() (v4, v6 int)
	logger      *logrus.Logger
}

func (s *scrubMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.ScrubPacketsDesc
	ch <- metrics.ScrubBytesDesc
	ch <- metrics.ScrubSlowPathDesc
	ch <- metrics.ScrubTTLExpiredDesc
	ch <- metrics.ScrubSlowPathLimitedDesc
	ch <- metrics.ScrubReadyDesc
	ch <- metrics.ScrubRuleMatchesDesc
	ch <- metrics.ScrubRulesActiveDesc
}

func (s *scrubMetrics) Collect(ch chan<- prometheus.Metric) {
	ready := 0.0
	if s.ready() == nil {
		ready = 1
	}
	ch <- prometheus.MustNewConstMetric(metrics.ScrubReadyDesc, prometheus.GaugeValue, ready)

	if s.ruleCounts != nil {
		v4, v6 := s.ruleCounts()
		ch <- prometheus.MustNewConstMetric(metrics.ScrubRulesActiveDesc, prometheus.GaugeValue, float64(v4), "ipv4")
		ch <- prometheus.MustNewConstMetric(metrics.ScrubRulesActiveDesc, prometheus.GaugeValue, float64(v6), "ipv6")
	}
	if s.ruleMatches != nil {
		if matches, err := s.ruleMatches(); err != nil {
			s.logger.WithError(err).Warn("Failed to read rule match counters")
		} else {
			for action, name := range ebpf.RuleActionNames {
				ch <- prometheus.MustNewConstMetric(metrics.ScrubRuleMatchesDesc, prometheus.CounterValue, float64(matches[action]), name)
			}
		}
	}

	st, err := s.stats()
	if err != nil {
		s.logger.WithError(err).Warn("Failed to read scrub counters")
		return
	}
	for v, verdict := range ebpf.ScrubVerdictNames {
		for f, family := range ebpf.ScrubFamilyNames {
			c := st.Verdicts[v][f]
			ch <- prometheus.MustNewConstMetric(metrics.ScrubPacketsDesc, prometheus.CounterValue, float64(c.Packets), verdict, family)
			ch <- prometheus.MustNewConstMetric(metrics.ScrubBytesDesc, prometheus.CounterValue, float64(c.Bytes), verdict, family)
		}
	}
	for r, reason := range ebpf.ScrubSlowReasonNames {
		ch <- prometheus.MustNewConstMetric(metrics.ScrubSlowPathDesc, prometheus.CounterValue, float64(st.SlowPath[r]), reason)
	}
	ch <- prometheus.MustNewConstMetric(metrics.ScrubTTLExpiredDesc, prometheus.CounterValue, float64(st.SlowPath[ebpf.ScrubSlowTTL]))
	ch <- prometheus.MustNewConstMetric(metrics.ScrubSlowPathLimitedDesc, prometheus.CounterValue, float64(st.SlowLimited))
}
