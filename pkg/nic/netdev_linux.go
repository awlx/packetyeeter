//go:build linux

package nic

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// ErrNoNetdevFamily means the kernel predates the netdev netlink family (6.3),
// so XDP features cannot be queried; it does not mean XDP is unsupported.
var ErrNoNetdevFamily = errors.New("netdev netlink family not available (kernel < 6.3)")

const (
	netdevCmdDevGet           = 1
	netdevAttrIfindex         = 1
	netdevAttrXDPFeatures     = 3
	netdevAttrXDPZCMaxSegs    = 4
	netdevAttrXDPRxMetaFeatrs = 5
)

// QueryDevFeatures asks the netdev netlink family which XDP actions and RX
// metadata kfuncs the interface's driver supports. Read-only.
func QueryDevFeatures(ifindex int) (DevFeatures, error) {
	fam, err := netlink.GenlFamilyGet("netdev")
	if err != nil {
		return DevFeatures{}, ErrNoNetdevFamily
	}
	req := nl.NewNetlinkRequest(int(fam.ID), unix.NLM_F_REQUEST)
	req.AddData(genlHeader{netdevCmdDevGet, 1})
	req.AddData(nl.NewRtAttr(netdevAttrIfindex, nl.Uint32Attr(uint32(ifindex))))
	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return DevFeatures{}, fmt.Errorf("netdev dev-get ifindex %d: %w", ifindex, err)
	}
	if len(msgs) == 0 || len(msgs[0]) < nl.SizeofGenlmsg {
		return DevFeatures{}, fmt.Errorf("netdev dev-get ifindex %d: empty reply", ifindex)
	}
	attrs, err := nl.ParseRouteAttr(msgs[0][nl.SizeofGenlmsg:])
	if err != nil {
		return DevFeatures{}, fmt.Errorf("netdev dev-get ifindex %d: %w", ifindex, err)
	}
	var f DevFeatures
	for _, a := range attrs {
		switch a.Attr.Type {
		case netdevAttrXDPFeatures:
			f.XDP = XDPFeatures(uintAttr(a.Value))
		case netdevAttrXDPZCMaxSegs:
			f.ZCMaxSegs = uint32(uintAttr(a.Value))
		case netdevAttrXDPRxMetaFeatrs:
			f.RxMetadata = RxMetadata(uintAttr(a.Value))
		}
	}
	return f, nil
}

// genlHeader is a genlmsghdr with its reserved bytes zeroed: nl.Genlmsg
// serialises 4 bytes from a 2-byte struct, and strictly validated families
// such as netdev reject a non-zero reserved field with EINVAL.
type genlHeader [2]uint8

func (h genlHeader) Len() int { return nl.SizeofGenlmsg }

func (h genlHeader) Serialize() []byte { return []byte{h[0], h[1], 0, 0} }

// uintAttr decodes a netlink "uint" attribute, which is 4 or 8 bytes.
func uintAttr(b []byte) uint64 {
	switch {
	case len(b) >= 8:
		return binary.NativeEndian.Uint64(b)
	case len(b) >= 4:
		return uint64(binary.NativeEndian.Uint32(b))
	default:
		return 0
	}
}

// XDPAttachMode returns the IFLA_XDP_ATTACHED mode and program id on ifindex.
func XDPAttachMode(ifindex int) (mode uint32, progID uint32, err error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return 0, 0, err
	}
	x := link.Attrs().Xdp
	if x == nil || !x.Attached {
		return AttachNone, 0, nil
	}
	return x.AttachMode, x.ProgId, nil
}
