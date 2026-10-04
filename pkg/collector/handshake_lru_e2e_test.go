//go:build linux && e2e_ebpf

// Checks the scrub handshake map sizing against the kernel's per-CPU LRU
// split. Needs root and the compiled eBPF object.
//
//	sudo -E go test -tags e2e_ebpf -run TestScrubHandshake -v ./pkg/collector/
package collector

import (
	"runtime"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"PacketYeeter/pkg/collector/ebpf"
)

func TestScrubHandshakeMapsSizedAtLoad(t *testing.T) {
	for _, mode := range []ebpf.HandshakeLRU{ebpf.HandshakeLRUAuto, ebpf.HandshakeLRUCommon} {
		t.Run(string(mode), func(t *testing.T) {
			l := ebpf.NewLoader(ebpf.LoaderConfig{Mode: ebpf.ModeScrub, HandshakeLRU: mode})
			if err := l.Load(); err != nil {
				t.Fatalf("load: %v", err)
			}
			defer l.Close()
			want := l.HandshakeSizing()
			if mode == ebpf.HandshakeLRUCommon && want.PerCPU {
				t.Fatal("common mode chose per-CPU lists")
			}
			m := l.GetMaps()
			for name, hm := range map[string]*cebpf.Map{"v4": m.PendingHandshakes, "v6": m.PendingHandshakesV6} {
				info, err := hm.Info()
				if err != nil {
					t.Fatal(err)
				}
				perCPU := info.Flags&unix.BPF_F_NO_COMMON_LRU != 0
				if info.MaxEntries != want.Entries || perCPU != want.PerCPU {
					t.Errorf("%s: max_entries %d per-CPU %v, want %d per-CPU %v", name, info.MaxEntries, perCPU, want.Entries, want.PerCPU)
				}
			}
			t.Logf("%s: %+v, per-CPU share %d", mode, want, want.PerCPUShare())
		})
	}
}

// One CPU taking the whole flood keeps PerCPUShare entries with per-CPU
// lists (the kernel does not borrow from other CPUs) and the whole map with
// the common list; the sizing must hand online CPUs their share either way.
func TestScrubHandshakeSingleCPURetention(t *testing.T) {
	possible, err := cebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	online, err := ebpf.OnlineCPUs()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []ebpf.HandshakeLRU{ebpf.HandshakeLRUAuto, ebpf.HandshakeLRUCommon} {
		t.Run(string(mode), func(t *testing.T) {
			s := ebpf.SizeScrubHandshakes(mode, possible, online)
			spec := &cebpf.MapSpec{Name: "hs_retention", Type: cebpf.LRUHash, KeySize: 12, ValueSize: 24, MaxEntries: s.Entries}
			if s.PerCPU {
				spec.Flags = unix.BPF_F_NO_COMMON_LRU
			}
			hm, err := cebpf.NewMap(spec)
			if err != nil {
				t.Fatal(err)
			}
			defer hm.Close()

			kept := fillFromOneCPU(t, hm, int(s.Entries))
			share := int(s.PerCPUShare())
			t.Logf("%s: %d possible, %d online, %d entries, one CPU kept %d (share %d)", mode, possible, online, s.Entries, kept, share)
			if kept < share*9/10 {
				t.Fatalf("one CPU kept %d entries, want about its share %d", kept, share)
			}
			if s.PerCPU && share*s.Online < ebpf.ScrubHandshakeEntries*9/10 {
				t.Fatalf("online CPUs hold %d together, want about %d", share*s.Online, ebpf.ScrubHandshakeEntries)
			}
		})
	}
}

// fillFromOneCPU inserts n distinct keys from CPU 0 and returns how many
// remain.
func fillFromOneCPU(t *testing.T, hm *cebpf.Map, n int) int {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var prev unix.CPUSet
	if err := unix.SchedGetaffinity(0, &prev); err != nil {
		t.Fatal(err)
	}
	// Restore before UnlockOSThread hands the thread back to the scheduler,
	// so later tests do not inherit a thread pinned to CPU 0.
	defer func() {
		if err := unix.SchedSetaffinity(0, &prev); err != nil {
			t.Errorf("restore CPU affinity: %v", err)
		}
	}()
	var set unix.CPUSet
	set.Set(0)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		t.Fatal(err)
	}
	type key struct {
		Saddr, Daddr uint32
		Sport, Dport uint16
	}
	const chunk = 4096
	keys := make([]key, 0, chunk)
	vals := make([][24]byte, chunk)
	for i := range n {
		keys = append(keys, key{Saddr: uint32(i), Daddr: 0x0a000001, Sport: uint16(i), Dport: 80})
		if len(keys) == chunk || i == n-1 {
			if _, err := hm.BatchUpdate(keys, vals[:len(keys)], nil); err != nil {
				t.Fatalf("fill: %v", err)
			}
			keys = keys[:0]
		}
	}
	kept := 0
	var k key
	var v [24]byte
	it := hm.Iterate()
	for it.Next(&k, &v) {
		kept++
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return kept
}
