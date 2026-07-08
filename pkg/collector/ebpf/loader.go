//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:embed c/protector.bpf.*
var bpfFS embed.FS

type Loader struct {
	coll  *ebpf.Collection
	maps  *Maps
	links []link.Link // XDP
	iface string

	// TC Filter objects
	ingressFilter *netlink.BpfFilter
	egressFilter  *netlink.BpfFilter
}

func NewLoader(iface string) *Loader {
	return &Loader{
		iface: iface,
	}
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
		OffenderEvents:      l.coll.Maps["offendoor_events"],
		OffenderEventsV6:    l.coll.Maps["offendoor_events_v6"],
		AllowListV4:         l.coll.Maps["allowlist_v4"],
		AllowListV6:         l.coll.Maps["allowlist_v6"],
		PolicyV4:            l.coll.Maps["policy_v4"],
		PolicyV6:            l.coll.Maps["policy_v6"],
		PolicyBlocks:        l.coll.Maps["policy_blocks"],
		PolicyBlocksV6:      l.coll.Maps["policy_blocks_v6"],
		Events:              l.coll.Maps["events"],
	}

	return nil
}

func (l *Loader) Attach() error {
	iface, err := net.InterfaceByName(l.iface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", l.iface, err)
	}

	// 1. Attach XDP
	xdpProg := l.coll.Programs["xdp_filter"]
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
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
