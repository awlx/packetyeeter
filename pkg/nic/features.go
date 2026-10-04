// Package nic inspects a network interface for scrub-mode suitability and
// predicts its xdp_scrub throughput from a driver cost model
// (docs/scrub-hardware.md).
package nic

import "strings"

// XDPFeatures mirrors enum netdev_xdp_act (include/uapi/linux/netdev.h), as
// reported by the netdev netlink family since Linux 6.3.
type XDPFeatures uint64

const (
	XDPBasic XDPFeatures = 1 << iota
	XDPRedirect
	XDPNdoXmit
	XDPXskZerocopy
	XDPHWOffload
	XDPRxSG
	XDPNdoXmitSG
)

var xdpFeatureNames = []struct {
	f    XDPFeatures
	name string
}{
	{XDPBasic, "basic"},
	{XDPRedirect, "redirect"},
	{XDPNdoXmit, "ndo-xmit"},
	{XDPXskZerocopy, "xsk-zerocopy"},
	{XDPHWOffload, "hw-offload"},
	{XDPRxSG, "rx-sg"},
	{XDPNdoXmitSG, "ndo-xmit-sg"},
}

func (f XDPFeatures) String() string {
	var out []string
	for _, n := range xdpFeatureNames {
		if f&n.f != 0 {
			out = append(out, n.name)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}

// RxMetadata mirrors enum netdev_xdp_rx_metadata: the bpf_xdp_metadata_rx_*
// kfuncs the driver implements.
type RxMetadata uint64

const (
	RxMetaTimestamp RxMetadata = 1 << iota
	RxMetaHash
	RxMetaVLANTag
)

func (m RxMetadata) String() string {
	var out []string
	if m&RxMetaTimestamp != 0 {
		out = append(out, "timestamp")
	}
	if m&RxMetaHash != 0 {
		out = append(out, "hash")
	}
	if m&RxMetaVLANTag != 0 {
		out = append(out, "vlan-tag")
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}

// DevFeatures is what the netdev netlink family reports for one interface.
type DevFeatures struct {
	XDP        XDPFeatures
	ZCMaxSegs  uint32
	RxMetadata RxMetadata
}

// XDP attach modes as in IFLA_XDP_ATTACHED.
const (
	AttachNone    = 0
	AttachDriver  = 1
	AttachGeneric = 2
	AttachHW      = 3
	AttachMulti   = 4
)

// AttachModeName names an IFLA_XDP_ATTACHED value the way iproute2 does.
func AttachModeName(mode uint32) string {
	switch mode {
	case AttachNone:
		return "none"
	case AttachDriver:
		return "native (xdpdrv)"
	case AttachGeneric:
		return "generic (xdpgeneric/skb)"
	case AttachHW:
		return "offloaded (xdpoffload)"
	case AttachMulti:
		return "multiple"
	default:
		return "unknown"
	}
}

// ScrubPortWarnings explains attach states of a scrub-mode port ("outside"
// or "inside") that cost throughput or lose forwarded traffic. f may be nil
// when the kernel cannot report driver features.
func ScrubPortWarnings(role string, generic bool, f *DevFeatures) []string {
	var w []string
	if generic {
		w = append(w, "generic (skb) XDP: every packet gets an skb before xdp_scrub runs, "+
			"several times slower than native; use for labs only")
	}
	if generic || f == nil {
		return w
	}
	switch role {
	case "outside":
		if f.XDP&XDPRedirect == 0 {
			w = append(w, "driver does not advertise XDP_REDIRECT support; forwarded frames will be dropped")
		}
	case "inside":
		if f.XDP&XDPNdoXmit == 0 {
			w = append(w, "driver does not advertise ndo_xdp_xmit; frames redirected to this port will be dropped")
		}
	}
	return w
}
