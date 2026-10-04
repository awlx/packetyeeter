//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"

	"PacketYeeter/pkg/nic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:embed c/protector.bpf.*
var bpfFS embed.FS

// LoaderConfig selects the programs to load and where to attach them.
type LoaderConfig struct {
	Mode         Mode
	Interface    string // the protected host's interface, or the outside port in scrub mode
	InsideIface  string // scrub mode only
	XDPMode      XDPMode
	AllowGeneric bool // scrub mode only
	Fingerprints bool // scrub mode only
	SynCookies   bool // scrub mode only
}

type Loader struct {
	cfg        LoaderConfig
	coll       *ebpf.Collection
	maps       *Maps
	links      []link.Link // XDP
	iface      string
	scrubLink  link.Link
	outsideIdx int
	scrubPorts []ScrubPort

	// TC Filter objects
	ingressFilter *netlink.BpfFilter
	egressFilter  *netlink.BpfFilter
}

func NewLoader(cfg LoaderConfig) *Loader {
	if cfg.Mode == "" {
		cfg.Mode = ModeHost
	}
	if cfg.XDPMode == "" {
		cfg.XDPMode = XDPModeAuto
	}
	return &Loader{
		cfg:   cfg,
		iface: cfg.Interface,
	}
}

// Only the mode's own programs are loaded, so scrub-only code can never make
// host mode fail verification, and vice versa.
var modePrograms = map[Mode][]string{
	ModeHost:  {"xdp_filter", "tc_ingress_syn_monitor", "tc_egress_synack_monitor"},
	ModeScrub: {"xdp_scrub", "xdp_pass_inside"},
}

func (l *Loader) Load() error {
	bpfObj, err := bpfFS.ReadFile("c/protector.bpf.o")
	if err != nil {
		return fmt.Errorf("failed to read embedded BPF object: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObj))
	if err != nil {
		return fmt.Errorf("failed to load BPF spec: %w", err)
	}
	keep, ok := modePrograms[l.cfg.Mode]
	if !ok {
		return fmt.Errorf("unknown mode %q", l.cfg.Mode)
	}
	for name := range spec.Programs {
		if !slices.Contains(keep, name) {
			delete(spec.Programs, name)
		}
	}
	// Each mode tracks handshakes in its own map pair; the other pair is
	// preallocated and large, so it is not created at all.
	handshakes, handshakesV6 := "pending_handshakes", "pending_handshakes_v6"
	unused := []string{"scrub_handshakes", "scrub_handshakes_v6"}
	if l.cfg.Mode == ModeScrub {
		handshakes, handshakesV6 = "scrub_handshakes", "scrub_handshakes_v6"
		unused = []string{"pending_handshakes", "pending_handshakes_v6"}
	}
	for _, name := range unused {
		delete(spec.Maps, name)
	}

	// The fingerprint maps preallocate per-CPU values (2 MiB per CPU for
	// both); shrink them when nothing reads them.
	if l.cfg.Mode != ModeScrub || !l.cfg.Fingerprints {
		for _, name := range []string{"fingerprints_a", "fingerprints_b"} {
			if m, ok := spec.Maps[name]; ok {
				m.MaxEntries = 1
			}
		}
	}

	// Disabled, the verifier prunes the cookie code and these maps stay
	// unused; the verified-source LRUs alone preallocate tens of MiB.
	if l.cfg.Mode == ModeScrub && l.cfg.SynCookies {
		if err := checkSynCookieSupport(); err != nil {
			return err
		}
		v, ok := spec.Variables["scrub_syncookies"]
		if !ok {
			return errors.New("BPF object has no scrub_syncookies variable")
		}
		if err := v.Set(uint32(1)); err != nil {
			return fmt.Errorf("enable SYN cookies: %w", err)
		}
	} else {
		for _, name := range []string{"syncookie_verified_v4", "syncookie_verified_v6", "syncookie_syn_rate", "syncookie_active"} {
			if m, ok := spec.Maps[name]; ok {
				m.MaxEntries = 1
			}
		}
	}

	l.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %v", err)
	}

	l.maps = &Maps{
		BlockedIPs:          l.coll.Maps["blocked_ips"],
		BlockedIPsV6:        l.coll.Maps["blocked_ips_v6"],
		PendingHandshakes:   l.coll.Maps[handshakes],
		PendingHandshakesV6: l.coll.Maps[handshakesV6],
		ICMPRates:           l.coll.Maps["icmp_rates"],
		ICMPRatesV6:         l.coll.Maps["icmp_rates_v6"],
		BadFlags:            l.coll.Maps["bad_flags"],
		BadFlagsV6:          l.coll.Maps["bad_flags_v6"],
		ConfigMap:           l.coll.Maps["config_map"],
		UDPRates:            l.coll.Maps["udp_rates"],
		UDPRatesV6:          l.coll.Maps["udp_rates_v6"],
		AllowListV4:         l.coll.Maps["allowlist_v4"],
		AllowListV6:         l.coll.Maps["allowlist_v6"],
		PolicyV4:            l.coll.Maps["policy_v4"],
		PolicyV6:            l.coll.Maps["policy_v6"],
		PolicyBlocks:        l.coll.Maps["policy_blocks"],
		PolicyBlocksV6:      l.coll.Maps["policy_blocks_v6"],
		Events:              l.coll.Maps["events"],
		Incidents:           l.coll.Maps["incidents"],
		EgressBytes:         l.coll.Maps["egress_bytes"],
		EgressBytesV6:       l.coll.Maps["egress_bytes_v6"],
		ScrubStats:          l.coll.Maps["scrub_stats"],
		TxPorts:             l.coll.Maps["tx_ports"],
		LocalAddrsV4:        l.coll.Maps["local_addrs_v4"],
		LocalAddrsV6:        l.coll.Maps["local_addrs_v6"],
		ScrubRules:          l.coll.Maps["scrub_rules"],
		RuleBuckets:         l.coll.Maps["rule_buckets"],
		RuleMatchCounts:     l.coll.Maps["rule_matches"],
		RulesV4:             l.coll.Maps["rules_v4"],
		RulesV6:             l.coll.Maps["rules_v6"],
		FingerprintsA:       l.coll.Maps["fingerprints_a"],
		FingerprintsB:       l.coll.Maps["fingerprints_b"],
		FPOverflow:          l.coll.Maps["fingerprint_overflow"],
		SynCookieStats:      l.coll.Maps["syncookie_stats"],
		SynCookieVerifiedV4: l.coll.Maps["syncookie_verified_v4"],
		SynCookieVerifiedV6: l.coll.Maps["syncookie_verified_v6"],
		RulesTrieSpecV4:     innerSpec(spec, "rules_v4"),
		RulesTrieSpecV6:     innerSpec(spec, "rules_v6"),
	}

	return nil
}

// checkSynCookieSupport refuses SYN cookies on kernels that cannot generate
// them in XDP, instead of loading a program whose challenges always fail.
func checkSynCookieSupport() error {
	for _, fn := range []asm.BuiltinFunc{
		asm.FnTcpRawGenSyncookieIpv4, asm.FnTcpRawGenSyncookieIpv6,
		asm.FnTcpRawCheckSyncookieIpv4, asm.FnTcpRawCheckSyncookieIpv6,
	} {
		if err := features.HaveProgramHelper(ebpf.XDP, fn); err != nil {
			return fmt.Errorf("-scrub-syn-cookies needs Linux 6.0 or later (XDP helper %s unavailable): %w", fn, err)
		}
	}
	// Without CONFIG_SYN_COOKIES the helpers exist but always fail.
	if _, err := os.Stat("/proc/sys/net/ipv4/tcp_syncookies"); err != nil {
		return fmt.Errorf("-scrub-syn-cookies needs a kernel built with CONFIG_SYN_COOKIES: %w", err)
	}
	return nil
}

func innerSpec(spec *ebpf.CollectionSpec, outer string) *ebpf.MapSpec {
	if m, ok := spec.Maps[outer]; ok && m.InnerMap != nil {
		return m.InnerMap.Copy()
	}
	return nil
}

func xdpAttachFlags(mode XDPMode) link.XDPAttachFlags {
	switch mode {
	case XDPModeNative:
		return link.XDPDriverMode
	case XDPModeGeneric:
		return link.XDPGenericMode
	default:
		return 0
	}
}

func (l *Loader) Attach() error {
	if l.cfg.Mode == ModeScrub {
		return l.attachScrub()
	}

	iface, err := net.InterfaceByName(l.iface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", l.iface, err)
	}

	// 1. Attach XDP
	xdpProg := l.coll.Programs["xdp_filter"]
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
		Flags:     xdpAttachFlags(l.cfg.XDPMode),
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP: %w", err)
	}
	l.links = append(l.links, xdpLink)

	// 2. Attach TC
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	netlink.QdiscAdd(qdisc) // Ignore error

	// Ingress
	ingressProg := l.coll.Programs["tc_ingress_syn_monitor"]
	l.ingressFilter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.MakeHandle(0xffff, 0xfff2),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           ingressProg.FD(),
		Name:         "tc_ingress_syn_monitor",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(l.ingressFilter); err != nil {
		return fmt.Errorf("failed to attach TC Ingress: %w", err)
	}

	// Egress
	egressProg := l.coll.Programs["tc_egress_synack_monitor"]
	l.egressFilter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.MakeHandle(0xffff, 0xfff3),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           egressProg.FD(),
		Name:         "tc_egress_synack_monitor",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(l.egressFilter); err != nil {
		return fmt.Errorf("failed to attach TC Egress: %w", err)
	}

	return nil
}

// attachScrub wires the inside port first, so xdp_scrub never runs without a
// redirect target.
func (l *Loader) attachScrub() error {
	outside, err := net.InterfaceByName(l.cfg.Interface)
	if err != nil {
		return fmt.Errorf("outside interface %s not found: %w", l.cfg.Interface, err)
	}
	inside, err := net.InterfaceByName(l.cfg.InsideIface)
	if err != nil {
		return fmt.Errorf("inside interface %s not found: %w", l.cfg.InsideIface, err)
	}
	if outside.Index == inside.Index {
		return fmt.Errorf("outside and inside interface are both %s", outside.Name)
	}

	insideLink, insideGeneric, err := l.attachXDPWithMode(l.coll.Programs["xdp_pass_inside"], inside, false)
	if err != nil {
		return fmt.Errorf("inside interface %s does not accept XDP: %w", inside.Name, err)
	}
	l.links = append(l.links, insideLink)

	if err := l.maps.TxPorts.Put(uint32(inside.Index), uint32(inside.Index)); err != nil {
		return fmt.Errorf("add inside interface %s to tx_ports: %w", inside.Name, err)
	}

	// Native redirects into a port without native XDP have no ndo_xdp_xmit
	// (or, on ixgbe/i40e, no XDP TX rings) and are dropped, so a generic
	// inside port keeps the outside generic too.
	scrubLink, outsideGeneric, err := l.attachXDPWithMode(l.coll.Programs["xdp_scrub"], outside, insideGeneric)
	if err != nil {
		return fmt.Errorf("attach xdp_scrub to %s: %w", outside.Name, err)
	}
	l.links = append(l.links, scrubLink)
	l.scrubLink = scrubLink
	l.outsideIdx = outside.Index
	l.scrubPorts = []ScrubPort{
		scrubPort("outside", outside, outsideGeneric),
		scrubPort("inside", inside, insideGeneric),
	}
	return nil
}

// ScrubPort is how one scrub-mode port ended up attached.
type ScrubPort struct {
	Role     string
	Name     string
	Generic  bool
	Features *nic.DevFeatures // nil when the kernel cannot report them
	// FeaturesErr is set when Features is nil.
	FeaturesErr error
}

func scrubPort(role string, iface *net.Interface, generic bool) ScrubPort {
	p := ScrubPort{Role: role, Name: iface.Name, Generic: generic}
	// Queried after attaching: veth, ixgbe and i40e only advertise
	// ndo-xmit once an XDP program is on the port.
	f, err := nic.QueryDevFeatures(iface.Index)
	if err == nil {
		p.Features = &f
	} else {
		p.FeaturesErr = err
	}
	return p
}

// ScrubPorts reports the attach mode and driver XDP features of the outside
// and inside port, in that order; empty outside scrub mode.
func (l *Loader) ScrubPorts() []ScrubPort {
	return l.scrubPorts
}

// attachXDPWithMode refuses generic XDP in scrub mode unless allowed, because
// it is far too slow to scrub at line rate and the kernel would otherwise fall
// back to it silently.
// preferGeneric skips the native attempt in auto mode; it is only set once
// another port already fell back, which requires AllowGeneric.
func (l *Loader) attachXDPWithMode(prog *ebpf.Program, iface *net.Interface, preferGeneric bool) (link.Link, bool, error) {
	opts := link.XDPOptions{Program: prog, Interface: iface.Index}
	generic := func() (link.Link, bool, error) {
		opts.Flags = link.XDPGenericMode
		lnk, err := link.AttachXDP(opts)
		return lnk, true, err
	}
	switch l.cfg.XDPMode {
	case XDPModeGeneric:
		if !l.cfg.AllowGeneric {
			return nil, false, errors.New("generic XDP requires -allow-generic")
		}
		return generic()
	case XDPModeNative:
		opts.Flags = link.XDPDriverMode
		lnk, err := link.AttachXDP(opts)
		return lnk, false, err
	}

	if preferGeneric && l.cfg.AllowGeneric {
		return generic()
	}
	opts.Flags = link.XDPDriverMode
	lnk, err := link.AttachXDP(opts)
	if err != nil && l.cfg.AllowGeneric {
		return generic()
	}
	if err != nil {
		return nil, false, fmt.Errorf("native XDP unavailable (pass -allow-generic for labs): %w", err)
	}
	return lnk, false, nil
}

// ScrubAttached reports whether xdp_scrub is still attached to the outside port.
func (l *Loader) ScrubAttached() error {
	if l.scrubLink == nil {
		return errors.New("xdp_scrub not attached")
	}
	info, err := l.scrubLink.Info()
	if err != nil {
		return fmt.Errorf("query xdp_scrub link: %w", err)
	}
	xdp := info.XDP()
	if xdp == nil || int(xdp.Ifindex) != l.outsideIdx {
		return errors.New("xdp_scrub link detached from outside interface")
	}
	return nil
}

func (l *Loader) Close() {
	if l.ingressFilter != nil {
		netlink.FilterDel(l.ingressFilter)
	}
	if l.egressFilter != nil {
		netlink.FilterDel(l.egressFilter)
	}
	// Reverse attach order: in scrub mode xdp_scrub must detach before
	// xdp_pass_inside, or redirects to the inside port are dropped by drivers
	// that need an XDP program on the target (ixgbe, i40e, veth).
	for i := len(l.links) - 1; i >= 0; i-- {
		l.links[i].Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
}

// Program returns a loaded program by name, e.g. for BPF_PROG_TEST_RUN.
func (l *Loader) Program(name string) *ebpf.Program {
	if l.coll == nil {
		return nil
	}
	return l.coll.Programs[name]
}

func (l *Loader) GetMaps() *Maps {
	return l.maps
}
