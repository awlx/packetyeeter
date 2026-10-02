package ebpf

import "testing"

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
	if len(ScrubVerdictNames) != 4 || len(ScrubFamilyNames) != 3 || len(ScrubSlowReasonNames) != scrubStatsSize-scrubSlowBase {
		t.Error("label names out of sync with scrub_stats layout")
	}
}
