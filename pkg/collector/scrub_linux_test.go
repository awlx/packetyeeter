//go:build linux

package collector

import (
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestRouteMayUseLink(t *testing.T) {
	multipath := netlink.Route{MultiPath: []*netlink.NexthopInfo{{LinkIndex: 3}, {LinkIndex: 7}}}
	for name, tc := range map[string]struct {
		route netlink.Route
		want  bool
	}{
		"direct":          {netlink.Route{LinkIndex: 7, Type: unix.RTN_UNICAST}, true},
		"nexthop object":  {netlink.Route{Type: unix.RTN_UNICAST}, true},
		"blackhole":       {netlink.Route{Type: unix.RTN_BLACKHOLE}, false},
		"other port":      {netlink.Route{LinkIndex: 3, Type: unix.RTN_UNICAST}, false},
		"multipath":       {multipath, true},
		"multipath other": {netlink.Route{MultiPath: []*netlink.NexthopInfo{{LinkIndex: 3}}}, false},
	} {
		if got := routeMayUseLink(tc.route, 7); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}
