package ebpf

import (
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeHost, "host": ModeHost, "scrub": ModeScrub} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseMode("router"); err == nil {
		t.Error("ParseMode(router) succeeded")
	}
}

func TestParseXDPMode(t *testing.T) {
	for in, want := range map[string]XDPMode{"": XDPModeAuto, "auto": XDPModeAuto, "native": XDPModeNative, "generic": XDPModeGeneric} {
		got, err := ParseXDPMode(in)
		if err != nil || got != want {
			t.Errorf("ParseXDPMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseXDPMode("offload"); err == nil {
		t.Error("ParseXDPMode(offload) succeeded")
	}
}

func TestCheckKernelRelease(t *testing.T) {
	for release, ok := range map[string]bool{
		"5.15.0-122-generic":        true,
		"6.8.0":                     true,
		"7.0.14-orbstack-00380":     true,
		"5.14.21-150500.55-default": false,
		"5.4.0-200-generic":         false,
		"4.19.0":                    false,
	} {
		if err := CheckKernelRelease(release, ScrubMinKernel); (err == nil) != ok {
			t.Errorf("CheckKernelRelease(%q) err = %v, want ok=%v", release, err, ok)
		}
	}
	if err := CheckKernelRelease("garbage", ScrubMinKernel); err == nil {
		t.Error("unparsable release accepted")
	}
}

func TestSumScrubStats(t *testing.T) {
	perIndex := make([][]ScrubCounter, scrubStatsSize)
	for i := range perIndex {
		perIndex[i] = []ScrubCounter{{Packets: 1, Bytes: 100}, {Packets: uint64(i), Bytes: 10}}
	}
	s := sumScrubStats(perIndex)

	// index = verdict*3 + family; drop/ipv6 is 1*3+1 = 4.
	if got := s.Verdicts[1][1]; got.Packets != 5 || got.Bytes != 110 {
		t.Errorf("drop/ipv6 = %+v, want {5 110}", got)
	}
	if got := s.SlowPath[ScrubSlowTTL]; got != 1+uint64(scrubSlowBase+ScrubSlowTTL) {
		t.Errorf("slow ttl = %d", got)
	}
	if got := s.SlowPath[ScrubSlowNotFwded]; got != 1+uint64(scrubSlowBase+ScrubSlowNotFwded) {
		t.Errorf("slow not_fwded = %d", got)
	}
	if s.SlowLimited != 1+uint64(scrubSlowLimited) {
		t.Errorf("slow limited = %d, want %d", s.SlowLimited, 1+scrubSlowLimited)
	}
	if len(ScrubVerdictNames) != 4 || len(ScrubFamilyNames) != 3 || len(ScrubSlowReasonNames) != scrubSlowReasons {
		t.Error("label names out of sync with scrub_stats layout")
	}
	if ScrubSlowReasonNames[ScrubSlowNotFwded] != "not_fwded" || ScrubSlowReasonNames[ScrubSlowTTL] != "ttl" {
		t.Error("slow-path reason constants out of sync with names")
	}
}

func TestScrubSlowPathPerCPU(t *testing.T) {
	for _, tc := range []struct {
		total uint32
		cpus  int
		want  uint32
	}{
		{0, 8, 0},
		{100000, 1, 100000},
		{100000, 8, 12500},
		{100001, 8, 12501},
		{1, 64, 1}, // never rounds a limit down to unlimited
		{100, 0, 100},
		{math.MaxUint32, 8, 536870912},
		{math.MaxUint32 - 1, 2, math.MaxUint32 / 2},
	} {
		if got := scrubSlowPathPerCPU(tc.total, tc.cpus); got != tc.want {
			t.Errorf("scrubSlowPathPerCPU(%d, %d) = %d, want %d", tc.total, tc.cpus, got, tc.want)
		}
	}
}

func TestSplitLocalAddrs(t *testing.T) {
	addrs := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1"), net.ParseIP("10.0.0.1")}
	v4, v6, err := splitLocalAddrs(addrs, 4)
	if err != nil || len(v4) != 2 || len(v6) != 1 {
		t.Fatalf("got %d v4, %d v6, %v; want 2, 1, nil", len(v4), len(v6), err)
	}

	many := make([]net.IP, 0, 5)
	for i := range 5 {
		many = append(many, net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1)))
	}
	if _, v6, err := splitLocalAddrs(many, 4); err == nil || !strings.Contains(err.Error(), "at most 4") || len(v6) != 5 {
		t.Errorf("over capacity: %d addrs, err = %v; want all 5 returned and a capacity error", len(v6), err)
	}
}

// TestScrubLayoutMatchesBPF guards the constants mirrored from protector.bpf.c.
func TestScrubLayoutMatchesBPF(t *testing.T) {
	src, err := os.ReadFile("c/protector.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		fmt.Sprintf("#define LOCAL_ADDRS_MAX %d\n", LocalAddrsMax),
		fmt.Sprintf("#define SCRUB_SLOW_REASONS      %d\n", scrubSlowReasons),
		fmt.Sprintf("#define SCRUB_SLOW_TTL          %d\n", ScrubSlowTTL),
		fmt.Sprintf("#define SCRUB_SLOW_NOT_FWDED    %d\n", ScrubSlowNotFwded),
		fmt.Sprintf("#define CONFIG_KEY_SCRUB_SLOW_PPS %d\n", configKeyScrubSlowPPS),
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("protector.bpf.c lacks %q", strings.TrimSpace(want))
		}
	}
}
