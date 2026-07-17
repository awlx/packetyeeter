package collector

import (
	"testing"

	"PacketYeeter/pkg/collector/ebpf"
)

// computePPSV6 must behave identically to the v4 computePPS: first sighting
// returns the raw count, a rolled window (LastTime advanced but Count dropped)
// reports the previous peak, and a steady window reports the current count.
func TestComputePPSV6(t *testing.T) {
	var key [16]byte
	key[0] = 0xfd

	prev := map[[16]byte]prevRate{}

	// First observation: no prior sample, return the current count.
	if got := computePPSV6(prev, key, ebpf.ICMPRate{LastTime: 100, Count: 3000}); got != 3000 {
		t.Fatalf("first observation pps = %v, want 3000", got)
	}

	// Window rolled (new window, count reset lower): report previous peak.
	if got := computePPSV6(prev, key, ebpf.ICMPRate{LastTime: 200, Count: 50}); got != 3000 {
		t.Fatalf("rolled window pps = %v, want previous peak 3000", got)
	}

	// Steady growth within accounting: report the current count.
	if got := computePPSV6(prev, key, ebpf.ICMPRate{LastTime: 300, Count: 4000}); got != 4000 {
		t.Fatalf("steady window pps = %v, want 4000", got)
	}
}

// computePPSV6 tracks each IPv6 source independently.
func TestComputePPSV6PerKey(t *testing.T) {
	prev := map[[16]byte]prevRate{}
	var a, b [16]byte
	a[15] = 1
	b[15] = 2

	computePPSV6(prev, a, ebpf.ICMPRate{LastTime: 10, Count: 100})
	computePPSV6(prev, b, ebpf.ICMPRate{LastTime: 10, Count: 200})
	if len(prev) != 2 {
		t.Fatalf("expected 2 tracked keys, got %d", len(prev))
	}
	// b's window rolls; a must be unaffected.
	if got := computePPSV6(prev, b, ebpf.ICMPRate{LastTime: 20, Count: 5}); got != 200 {
		t.Fatalf("key b rolled pps = %v, want 200", got)
	}
	if got := computePPSV6(prev, a, ebpf.ICMPRate{LastTime: 20, Count: 150}); got != 150 {
		t.Fatalf("key a pps = %v, want 150", got)
	}
}
