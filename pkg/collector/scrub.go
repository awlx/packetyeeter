package collector

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func validateModeConfig(cfg Config) error {
	if cfg.Mode != ebpf.ModeScrub {
		return nil
	}
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
// forwarding redirected traffic.
func checkForwarding(read sysctlReader, ipv6 bool) error {
	names := []string{"net/ipv4/ip_forward"}
	if ipv6 {
		names = append(names, "net/ipv6/conf/all/forwarding")
	}
	for _, name := range names {
		v, err := readSysctlInt(read, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if v != 1 {
			return fmt.Errorf("%s must be 1, is %d", strings.ReplaceAll(name, "/", "."), v)
		}
	}
	return nil
}

// checkScrubSysctls also rejects strict reverse-path filtering on the outside
// port: attack sources are spoofed, so it would drop slow-path packets.
func checkScrubSysctls(read sysctlReader, outside string, ipv6 bool) error {
	if err := checkForwarding(read, ipv6); err != nil {
		return err
	}
	all, err := readSysctlInt(read, "net/ipv4/conf/all/rp_filter")
	if err != nil {
		return fmt.Errorf("read rp_filter: %w", err)
	}
	ifName := strings.ReplaceAll(outside, ".", "/")
	port, err := readSysctlInt(read, "net/ipv4/conf/"+ifName+"/rp_filter")
	if err != nil {
		return fmt.Errorf("read rp_filter for %s: %w", outside, err)
	}
	// The kernel applies the larger of the two values.
	if max(all, port) == 1 {
		return fmt.Errorf("strict rp_filter on %s: set net.ipv4.conf.all.rp_filter and net.ipv4.conf.%s.rp_filter to 0 or 2", outside, outside)
	}
	return nil
}

// hasGlobalIPv6 decides whether IPv6 forwarding is required. Turning it on
// unconditionally would stop SLAAC on management interfaces of IPv4-only nodes.
func hasGlobalIPv6(ifaces ...string) bool {
	for _, name := range ifaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil && ipn.IP.IsGlobalUnicast() {
				return true
			}
		}
	}
	return false
}

func (c *Collector) preflightScrub() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return fmt.Errorf("uname: %w", err)
	}
	if err := ebpf.CheckKernelRelease(unix.ByteSliceToString(uts.Release[:]), ebpf.ScrubMinKernel); err != nil {
		return err
	}
	ipv6 := hasGlobalIPv6(c.Config.Interface, c.Config.InsideInterface)
	return checkScrubSysctls(procSysctl, c.Config.Interface, ipv6)
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
			return checkForwarding(procSysctl, hasGlobalIPv6(c.Config.Interface, c.Config.InsideInterface))
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
// the kernel (NOT_FWDED); the map only exempts it from scrubbing checks.
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

// scrubMetrics reads the kernel counters at scrape time, so the exported
// counters are exact rather than sampled by a poll loop.
type scrubMetrics struct {
	stats  func() (ebpf.ScrubStats, error)
	ready  func() error
	logger *logrus.Logger
}

func (s *scrubMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.ScrubPacketsDesc
	ch <- metrics.ScrubBytesDesc
	ch <- metrics.ScrubSlowPathDesc
	ch <- metrics.ScrubTTLExpiredDesc
	ch <- metrics.ScrubReadyDesc
}

func (s *scrubMetrics) Collect(ch chan<- prometheus.Metric) {
	ready := 0.0
	if s.ready() == nil {
		ready = 1
	}
	ch <- prometheus.MustNewConstMetric(metrics.ScrubReadyDesc, prometheus.GaugeValue, ready)

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
}
