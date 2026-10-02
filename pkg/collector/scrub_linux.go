//go:build linux

package collector

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func ipv6RouteDsts(name string) ([]*net.IPNet, error) {
	lnk, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	// List the whole main table: filtering by link would miss multipath
	// routes, whose next hops carry the interface.
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}
	idx := lnk.Attrs().Index
	var dsts []*net.IPNet
	for _, r := range routes {
		if routeMayUseLink(r, idx) {
			dsts = append(dsts, r.Dst)
		}
	}
	return dsts, nil
}

// routeMayUseLink also counts unicast routes without an interface: they use
// nexthop objects (RTA_NH_ID), which netlink does not resolve, so whether they
// leave via idx is unknown and IPv6 forwarding is required to be safe.
func routeMayUseLink(r netlink.Route, idx int) bool {
	if r.LinkIndex == idx {
		return true
	}
	if r.LinkIndex == 0 && len(r.MultiPath) == 0 && r.Type == unix.RTN_UNICAST {
		return true
	}
	for _, nh := range r.MultiPath {
		if nh != nil && nh.LinkIndex == idx {
			return true
		}
	}
	return false
}
