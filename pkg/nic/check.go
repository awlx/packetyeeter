package nic

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// Level of a check finding.
type Level string

const (
	LevelOK   Level = "ok"
	LevelInfo Level = "info"
	LevelWarn Level = "warn"
)

type Finding struct {
	Level Level
	Text  string
}

// Check turns a probe into findings, in display order. role is "outside",
// "inside" or "" (unknown).
func Check(info *Info, role string) []Finding {
	var fs []Finding
	add := func(l Level, format string, a ...any) { fs = append(fs, Finding{l, fmt.Sprintf(format, a...)}) }

	switch info.XDPMode {
	case AttachNone:
		add(LevelInfo, "no XDP program attached")
	case AttachDriver:
		add(LevelOK, "XDP attached in native mode (prog %q, id %d)", info.XDPProgName, info.XDPProgID)
	case AttachGeneric:
		add(LevelWarn, "XDP attached in generic (skb) mode (prog %q): several times slower than native; labs only",
			info.XDPProgName)
	default:
		add(LevelInfo, "XDP attached in %s mode", AttachModeName(info.XDPMode))
	}

	if info.Features != nil {
		f := info.Features
		if f.XDP&XDPBasic == 0 {
			add(LevelWarn, "driver %s has no native XDP: scrub mode would need -allow-generic", info.Driver)
		} else {
			add(LevelOK, "driver XDP features: %s", f.XDP)
		}
		if role != "inside" && f.XDP&XDPBasic != 0 && f.XDP&XDPRedirect == 0 {
			add(LevelWarn, "no XDP_REDIRECT: cannot be a scrub outside port")
		}
		if role != "outside" && f.XDP&XDPNdoXmit == 0 {
			msg := "no ndo_xdp_xmit: cannot be a scrub inside (redirect target) port"
			if info.XDPMode == AttachNone {
				msg += " (some drivers, e.g. veth, ixgbe, i40e, only advertise it once an XDP program is attached)"
			}
			add(LevelWarn, "%s", msg)
		}
		add(LevelInfo, "XDP RX metadata kfuncs: %s", f.RxMetadata)
	}

	if note, ok := DriverNotes[info.Driver]; ok {
		add(LevelWarn, "%s", note)
	}
	if p, ok := LookupDriver(info.Driver); ok {
		if p.SingleBufferMTU > 0 && info.MTU > p.SingleBufferMTU &&
			(info.Features == nil || info.Features.XDP&XDPRxSG == 0) {
			add(LevelWarn, "MTU %d exceeds %s's single-buffer XDP limit (~%d) and the driver reports no multi-buffer support: native attach will fail",
				info.MTU, info.Driver, p.SingleBufferMTU)
		}
	}

	for _, name := range []string{"large-receive-offload", "rx-gro-hw"} {
		if o, ok := info.Offloads[name]; ok && o.On {
			add(LevelWarn, "%s is on: most drivers refuse native XDP with it (ethtool -K %s %s off)",
				name, info.Name, map[string]string{"large-receive-offload": "lro", "rx-gro-hw": "rx-gro-hw"}[name])
		}
	}
	if o, ok := info.Offloads["receive-hashing"]; ok && !o.On && !o.Fixed {
		add(LevelWarn, "receive-hashing (RSS) is off: all traffic lands on one queue (ethtool -K %s rxhash on)", info.Name)
	}
	if o, ok := info.Offloads["hw-tc-offload"]; ok && o.On {
		add(LevelInfo, "hw-tc-offload is on: tc flower rules with skip_sw run in the NIC before XDP")
	}

	rxq := info.RxQueues
	if info.Channels != nil && info.Channels.Cur > 0 {
		rxq = info.Channels.Cur
	}
	localCPUs := info.CPUs
	if len(info.NUMACPUs) > 0 {
		localCPUs = len(info.NUMACPUs)
	}
	switch {
	case rxq <= 1 && info.CPUs > 1:
		add(LevelWarn, "a single RX queue: XDP runs on one core; raise with ethtool -L %s combined <n>", info.Name)
	case rxq < localCPUs:
		max := ""
		if info.Channels != nil && info.Channels.Max > 0 {
			max = fmt.Sprintf(", driver maximum %d", info.Channels.Max)
		}
		add(LevelInfo, "%d RX queues for %d CPUs on the NIC's NUMA node%s", rxq, localCPUs, max)
	default:
		add(LevelOK, "%d RX queues, %d CPUs on the NIC's NUMA node", rxq, localCPUs)
	}

	if len(info.IRQCPUs) > 0 && len(info.NUMACPUs) > 0 {
		var remote []int
		for _, c := range info.IRQCPUs {
			if !slices.Contains(info.NUMACPUs, c) {
				remote = append(remote, c)
			}
		}
		if len(remote) > 0 {
			add(LevelWarn, "NIC IRQs may fire on CPUs %v outside NUMA node %d: pin them to %s",
				remote, info.NUMANode, cpuList(info.NUMACPUs))
		}
	}
	if info.IRQBalance {
		add(LevelInfo, "irqbalance is running: it may move NIC IRQs during an attack; pin them for predictable XDP placement")
	}

	if r := info.Rings; r != nil && r.Cur > 0 {
		switch {
		case r.Cur < 1024 && r.Max >= 1024:
			add(LevelInfo, "RX ring %d (max %d): 1024-4096 absorbs bursts better (ethtool -G %s rx 2048)", r.Cur, r.Max, info.Name)
		default:
			add(LevelOK, "RX ring %d (max %d)", r.Cur, r.Max)
		}
	}
	if info.BusyPoll > 0 || info.NAPIDeferHardIRQs > 0 || info.ThreadedNAPI {
		add(LevelInfo, "NAPI tuning: busy_poll=%d napi_defer_hard_irqs=%d gro_flush_timeout=%d threaded=%t",
			info.BusyPoll, info.NAPIDeferHardIRQs, info.GROFlushTimeout, info.ThreadedNAPI)
	}
	for _, e := range info.Errors {
		add(LevelInfo, "%s", e)
	}
	return fs
}

func cpuList(cpus []int) string {
	parts := make([]string, len(cpus))
	for i, c := range cpus {
		parts[i] = fmt.Sprint(c)
	}
	return strings.Join(parts, ",")
}

// WriteReport prints the probe, findings and throughput prediction.
func WriteReport(w io.Writer, info *Info, role string) {
	fmt.Fprintf(w, "Interface %s (ifindex %d), kernel %s\n", info.Name, info.Ifindex, info.Kernel)
	fmt.Fprintf(w, "  driver %s %s, firmware %s, bus %s\n", orNA(info.Driver), info.DriverVersion,
		orNA(info.Firmware), orNA(info.BusInfo))
	speed := "unknown"
	if info.SpeedMbps > 0 {
		speed = fmt.Sprintf("%d Mb/s", info.SpeedMbps)
	}
	fmt.Fprintf(w, "  speed %s, MTU %d, NUMA node %d, %d CPUs, %d RX / %d TX queues, %d IRQ vectors\n",
		speed, info.MTU, info.NUMANode, info.CPUs, info.RxQueues, info.TxQueues, info.IRQs)
	fmt.Fprintln(w)
	for _, f := range Check(info, role) {
		fmt.Fprintf(w, "[%-4s] %s\n", f.Level, f.Text)
	}
	fmt.Fprintln(w)
	WritePrediction(w, info.Driver, info.SpeedMbps)
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}
