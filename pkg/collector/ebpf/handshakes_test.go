package ebpf

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestScrubHandshakeEntriesMatchesBPF(t *testing.T) {
	src, err := os.ReadFile("c/protector.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("#define HANDSHAKES_MAP_SIZE %d\n", ScrubHandshakeEntries); !strings.Contains(string(src), want) {
		t.Errorf("protector.bpf.c lacks %q", strings.TrimSpace(want))
	}
}

func TestSizeScrubHandshakes(t *testing.T) {
	for _, tc := range []struct {
		mode             HandshakeLRU
		possible, online int
		entries          uint32
		perCPU           bool
	}{
		// Bare metal: all possible CPUs online, unchanged from before.
		{HandshakeLRUAuto, 8, 8, 500000, true},
		{HandshakeLRUAuto, 64, 64, 500032, true},
		// A few hot-pluggable CPUs: grow so online CPUs keep their share.
		{HandshakeLRUAuto, 16, 8, 1000000, true},
		{HandshakeLRUAuto, 12, 8, 750000, true},
		// Possible far above online: the common LRU instead.
		{HandshakeLRUAuto, 128, 8, 500000, false},
		{HandshakeLRUPerCPU, 128, 8, 999936, true},
		{HandshakeLRUPerCPU, 3, 1, 999999, true},
		{HandshakeLRUCommon, 8, 8, 500000, false},
		// Unknown online count falls back to possible.
		{HandshakeLRUAuto, 4, 0, 500000, true},
	} {
		got := SizeScrubHandshakes(tc.mode, tc.possible, tc.online)
		if got.Entries != tc.entries || got.PerCPU != tc.perCPU {
			t.Errorf("%s %d/%d: got %d entries per-CPU=%v, want %d per-CPU=%v",
				tc.mode, tc.online, tc.possible, got.Entries, got.PerCPU, tc.entries, tc.perCPU)
		}
		if got.PerCPU && got.Entries%uint32(got.Possible) != 0 {
			t.Errorf("%s %d/%d: %d entries is not a multiple of the possible CPUs", tc.mode, tc.online, tc.possible, got.Entries)
		}
		if got.PerCPU && got.Entries > maxScrubHandshakeEntries {
			t.Errorf("%s %d/%d: %d entries exceeds the cap", tc.mode, tc.online, tc.possible, got.Entries)
		}
		if tc.mode == HandshakeLRUAuto && got.PerCPU && int(got.PerCPUShare())*got.Online < ScrubHandshakeEntries-got.Possible {
			t.Errorf("%d/%d: online CPUs hold %d entries together, want ~%d", tc.online, tc.possible, int(got.PerCPUShare())*got.Online, ScrubHandshakeEntries)
		}
	}
}

func TestParseCPUList(t *testing.T) {
	for s, want := range map[string]int{"0": 1, "0-7": 8, "0-3,8,10-11": 7} {
		if got, err := parseCPUList(s); err != nil || got != want {
			t.Errorf("parseCPUList(%q) = %d, %v; want %d", s, got, err, want)
		}
	}
	for _, s := range []string{"", "a", "3-1", "0-"} {
		if _, err := parseCPUList(s); err == nil {
			t.Errorf("parseCPUList(%q) succeeded", s)
		}
	}
}

func TestParseHandshakeLRU(t *testing.T) {
	if m, err := ParseHandshakeLRU(""); err != nil || m != HandshakeLRUAuto {
		t.Errorf("empty = %q, %v", m, err)
	}
	if _, err := ParseHandshakeLRU("shared"); err == nil {
		t.Error("accepted an unknown mode")
	}
}

func TestHandshakeSizingEstimatedBytes(t *testing.T) {
	if got := (HandshakeSizing{Entries: ScrubHandshakeEntries}).EstimatedBytes() >> 20; got != 111 {
		t.Errorf("500k entries = %d MiB, want 111", got)
	}
}
