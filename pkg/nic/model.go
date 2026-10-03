package nic

import (
	"fmt"
	"io"
	"math"
	"strings"
)

// The throughput model of docs/scrub-hardware.md: per packet, one core spends
//
//	driver RX + XDP dispatch (DropNs)                  every packet
//	+ xdp_scrub itself (Scenario.BPFNs × CPUScale)      every packet
//	+ redirect, devmap flush and TX completion (TxNs)  forwarded packets only
//
// DropNs and TxNs come from published XDP_DROP / XDP_REDIRECT per-core rates
// with a trivial program; BPFNs from kernel.bpf_stats_enabled run times of
// xdp_scrub in scripts/xdp_scrub_bench.sh. Every input is a [low, high] range
// and the prediction carries the spread through.

// Range is a [low, high] pair.
type Range [2]float64

// DriverProfile holds the driver costs of one driver family.
type DriverProfile struct {
	Name    string
	Drivers []string // kernel driver names, as ethtool -i reports them
	Native  bool     // native XDP with XDP_REDIRECT and ndo_xdp_xmit
	DropNs  Range    // ns/packet for XDP_DROP with a trivial program
	TxNs    Range    // extra ns/packet for XDP_REDIRECT through a devmap to a port of the same driver
	// SingleBufferMTU is the largest MTU native single-buffer XDP accepts
	// (0 = not modelled); multi-buffer capable drivers lift it.
	SingleBufferMTU int
	Basis           string // where the numbers come from
}

// Scenario is one traffic mix with xdp_scrub's measured program cost.
type Scenario struct {
	Name    string
	Desc    string
	BPFNs   Range // xdp_scrub run time on the reference core (Apple M2, VM)
	Forward bool  // forwarded (pays TxNs) rather than dropped
}

// CPUScale converts reference-core BPF time to a typical 2.5-3.5 GHz server
// core: map lookups and helper calls are memory- and branch-bound, and the
// reference core has a large L1/L2 and high IPC.
var CPUScale = Range{1.0, 1.6}

// Scenarios: BPFNs spans the typical runs of BPF_STATS=1
// scripts/xdp_scrub_bench.sh on one sender CPU (2026-10, kernel 7.0); see
// docs/scrub-hardware.md for the raw numbers.
var Scenarios = []Scenario{
	{"forward", "clean forwarding, no rules", Range{100, 120}, true},
	{"forward-rules", "clean forwarding, 4096 rules, 32 on the destination, worst-case miss", Range{290, 350}, true},
	{"rule-drop", "dropped by a matching DROP rule", Range{60, 85}, false},
	{"syn-flood", "random-source SYN flood (1 UDP : 3 SYN), forwarded, one LRU insert per SYN", Range{400, 520}, true},
}

// Profiles are per driver family. DropNs is 1/(published XDP_DROP Mpps per
// core); TxNs is 1/(XDP_REDIRECT Mpps per core) minus DropNs. Ranges span
// kernel versions and CPUs; drivers without published numbers borrow the
// nearest measured family and are marked "assumed" in Basis. Sources are in
// docs/scrub-hardware.md.
var Profiles = []DriverProfile{
	{Name: "NVIDIA ConnectX-4/5/6/7", Drivers: []string{"mlx5_core"}, Native: true,
		DropNs: Range{31, 50}, TxNs: Range{60, 100}, SingleBufferMTU: 3498,
		Basis: "measured: 20-32 Mpps/core drop, 7-8.7 Mpps/core devmap redirect"},
	{Name: "Intel E810", Drivers: []string{"ice"}, Native: true,
		DropNs: Range{40, 90}, TxNs: Range{50, 110}, SingleBufferMTU: 3046,
		Basis: "assumed from i40e: no published ice XDP_DROP/REDIRECT rates"},
	{Name: "Intel X710/XL710/XXV710", Drivers: []string{"i40e"}, Native: true,
		DropNs: Range{45, 90}, TxNs: Range{50, 110}, SingleBufferMTU: 3046,
		Basis: "measured: 6.7 Mpps/core devmap redirect (4.18, retpoline)"},
	{Name: "Intel 82599/X520/X540/X550", Drivers: []string{"ixgbe"}, Native: true,
		DropNs: Range{50, 100}, TxNs: Range{50, 110},
		Basis: "measured: 10.1 Mpps/core drop (with mitigations), 6.9 Mpps/core redirect"},
	{Name: "Broadcom NetXtreme-C/E", Drivers: []string{"bnxt_en"}, Native: true,
		DropNs: Range{50, 100}, TxNs: Range{60, 120},
		Basis: "assumed: no published bnxt XDP rates"},
	{Name: "Intel I210/I350/I225/I226 (1 GbE)", Drivers: []string{"igb", "igc"}, Native: true,
		DropNs: Range{60, 150}, TxNs: Range{80, 200},
		Basis: "assumed; 1 GbE line rate (1.49 Mpps) is below any per-core limit"},
	{Name: "AWS ENA", Drivers: []string{"ena"}, Native: true,
		DropNs: Range{80, 150}, TxNs: Range{100, 250}, SingleBufferMTU: 3498,
		Basis: "assumed; instance PPS allowances usually bind first"},
	{Name: "Google gVNIC", Drivers: []string{"gve"}, Native: true,
		DropNs: Range{80, 150}, TxNs: Range{100, 250},
		Basis: "assumed; VM PPS limits usually bind first"},
	{Name: "virtio-net", Drivers: []string{"virtio_net"}, Native: true,
		DropNs: Range{80, 200}, TxNs: Range{150, 400}, SingleBufferMTU: 3506,
		Basis: "assumed; depends on the host's vhost backend"},
	{Name: "veth (lab)", Drivers: []string{"veth"}, Native: true,
		DropNs: Range{150, 300}, TxNs: Range{200, 400},
		Basis: "lab only: frames are built from skbs"},
}

// DriverNotes flag drivers that cannot fill one of the scrub roles, whatever
// their speed (mainline as of 7.3; docs/scrub-hardware.md).
var DriverNotes = map[string]string{
	"mlx4_core": "mlx4 has no ndo_xdp_xmit: usable as outside port only, never as the inside port",
	"mlx4_en":   "mlx4 has no ndo_xdp_xmit: usable as outside port only, never as the inside port",
	"ixgbevf":   "ixgbevf XDP has no XDP_REDIRECT: cannot forward in scrub mode",
	"iavf":      "iavf has no XDP support upstream: scrub mode would need -allow-generic",
	"nfp":       "nfp has no ndo_xdp_xmit (inside port impossible) and its driver is in odd-fixes maintenance",
	"r8169":     "r8169 has no native XDP: scrub mode would need -allow-generic (labs only)",
}

// LookupDriver returns the profile for a kernel driver name.
func LookupDriver(driver string) (DriverProfile, bool) {
	for _, p := range Profiles {
		for _, d := range p.Drivers {
			if d == driver {
				return p, true
			}
		}
	}
	return DriverProfile{}, false
}

// Prediction is the per-core rate range for one scenario.
type Prediction struct {
	Scenario    Scenario
	PerCoreMpps Range // [pessimistic, optimistic]
}

// Predict returns per-core Mpps for every scenario on a driver profile.
func Predict(p DriverProfile) []Prediction {
	out := make([]Prediction, 0, len(Scenarios))
	for _, s := range Scenarios {
		lo := p.DropNs[0] + s.BPFNs[0]*CPUScale[0]
		hi := p.DropNs[1] + s.BPFNs[1]*CPUScale[1]
		if s.Forward {
			lo += p.TxNs[0]
			hi += p.TxNs[1]
		}
		out = append(out, Prediction{Scenario: s, PerCoreMpps: Range{1000 / hi, 1000 / lo}})
	}
	return out
}

// IMIXFrameBytes is the mean frame of the 7×64, 4×594, 1×1518 simple IMIX.
const IMIXFrameBytes = (7*64 + 4*594 + 1518) / 12.0

// LineRateMpps is the packet rate of a link full of frames of the given size
// (FCS included), counting preamble, SFD and inter-frame gap (20 bytes).
func LineRateMpps(speedMbps int, frameBytes float64) float64 {
	return float64(speedMbps) / ((frameBytes + 20) * 8)
}

// CoresFor is the number of cores needed for mpps at perCore Mpps each,
// assuming RSS spreads the load evenly.
func CoresFor(mpps, perCore float64) int {
	if perCore <= 0 {
		return 0
	}
	return int(math.Ceil(mpps / perCore))
}

// WritePrediction prints the model's per-core rates for driver and, when the
// speed is known, the cores needed for line rate.
func WritePrediction(w io.Writer, driver string, speedMbps int) {
	p, ok := LookupDriver(driver)
	if !ok {
		fmt.Fprintf(w, "No throughput model for driver %q; see docs/scrub-hardware.md for measuring it.\n", driver)
		return
	}
	fmt.Fprintf(w, "Predicted xdp_scrub throughput per core (%s; %s)\n", p.Name, p.Basis)
	fmt.Fprintln(w, "Model estimate, not a measurement: verify with docs/scrub-throughput.md.")
	header := fmt.Sprintf("  %-14s %-16s", "scenario", "Mpps/core")
	if speedMbps > 0 {
		header += fmt.Sprintf(" %-18s %-18s", "cores 64B line", "cores IMIX line")
	}
	fmt.Fprintln(w, header)
	for _, pr := range Predict(p) {
		line := fmt.Sprintf("  %-14s %-16s", pr.Scenario.Name,
			fmt.Sprintf("%.1f-%.1f", pr.PerCoreMpps[0], pr.PerCoreMpps[1]))
		if speedMbps > 0 {
			line += fmt.Sprintf(" %-18s %-18s",
				coresRange(LineRateMpps(speedMbps, 64), pr.PerCoreMpps),
				coresRange(LineRateMpps(speedMbps, IMIXFrameBytes), pr.PerCoreMpps))
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	if speedMbps > 0 {
		fmt.Fprintf(w, "  line rate at %d Mb/s: %.2f Mpps at 64B, %.2f Mpps IMIX\n", speedMbps,
			LineRateMpps(speedMbps, 64), LineRateMpps(speedMbps, IMIXFrameBytes))
	}
}

func coresRange(mpps float64, perCore Range) string {
	best, worst := CoresFor(mpps, perCore[1]), CoresFor(mpps, perCore[0])
	if best == worst {
		return fmt.Sprintf("%d", best)
	}
	return fmt.Sprintf("%d-%d", best, worst)
}
