//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/cilium/ebpf"
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
}

type Loader struct {
	cfg        LoaderConfig
	coll       *ebpf.Collection
	maps       *Maps
	links      []link.Link // XDP
	iface      string
	scrubLink  link.Link
	outsideIdx int

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

	l.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %v", err)
	}

	l.maps = &Maps{
		BlockedIPs:          l.coll.Maps["blocked_ips"],
		BlockedIPsV6:        l.coll.Maps["blocked_ips_v6"],
		PendingHandshakes:   l.coll.Maps["pending_handshakes"],
		PendingHandshakesV6: l.coll.Maps["pending_handshakes_v6"],
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

	insideLink, err := l.attachXDPWithMode(l.coll.Programs["xdp_pass_inside"], inside)
	if err != nil {
		return fmt.Errorf("inside interface %s does not accept XDP: %w", inside.Name, err)
	}
	l.links = append(l.links, insideLink)

	if err := l.maps.TxPorts.Put(uint32(inside.Index), uint32(inside.Index)); err != nil {
		return fmt.Errorf("add inside interface %s to tx_ports: %w", inside.Name, err)
	}

	scrubLink, err := l.attachXDPWithMode(l.coll.Programs["xdp_scrub"], outside)
	if err != nil {
		return fmt.Errorf("attach xdp_scrub to %s: %w", outside.Name, err)
	}
	l.links = append(l.links, scrubLink)
	l.scrubLink = scrubLink
	l.outsideIdx = outside.Index
	return nil
}

// attachXDPWithMode refuses generic XDP in scrub mode unless allowed, because
// it is far too slow to scrub at line rate and the kernel would otherwise fall
// back to it silently.
func (l *Loader) attachXDPWithMode(prog *ebpf.Program, iface *net.Interface) (link.Link, error) {
	opts := link.XDPOptions{Program: prog, Interface: iface.Index}
	switch l.cfg.XDPMode {
	case XDPModeGeneric:
		if !l.cfg.AllowGeneric {
			return nil, errors.New("generic XDP requires -allow-generic")
		}
		opts.Flags = link.XDPGenericMode
		return link.AttachXDP(opts)
	case XDPModeNative:
		opts.Flags = link.XDPDriverMode
		return link.AttachXDP(opts)
	}

	opts.Flags = link.XDPDriverMode
	lnk, err := link.AttachXDP(opts)
	if err != nil && l.cfg.AllowGeneric {
		opts.Flags = link.XDPGenericMode
		return link.AttachXDP(opts)
	}
	if err != nil {
		return nil, fmt.Errorf("native XDP unavailable (pass -allow-generic for labs): %w", err)
	}
	return lnk, nil
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
	for _, lnk := range l.links {
		lnk.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
}

func (l *Loader) GetMaps() *Maps {
	return l.maps
}
