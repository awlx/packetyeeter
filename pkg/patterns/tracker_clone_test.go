package patterns

import (
	"net"
	"testing"
)

// GetPattern's snapshot must be a full deep copy: mutating any reference field
// of the returned pattern must not corrupt the live tracked pattern. The IP
// slice was previously left aliased.
func TestGetPatternClonesIP(t *testing.T) {
	pt := NewPatternTracker(nil)
	ip := net.ParseIP("203.0.113.9")
	pt.RecordConnection(ip, ConnectionMetadata{PacketSize: 100, DestPort: 80})

	snap := pt.GetPattern(ip)
	if snap == nil || len(snap.IP) == 0 {
		t.Fatal("expected a pattern with a non-empty IP")
	}
	orig := append(net.IP(nil), snap.IP...)

	snap.IP[0] ^= 0xff // caller mutates its "independent" snapshot

	again := pt.GetPattern(ip)
	if !again.IP.Equal(orig) {
		t.Fatalf("mutating snapshot IP corrupted the live pattern: got %v want %v", again.IP, orig)
	}
}

// PatternSummary returns just the ML-feature fields, matching what a full
// GetPattern snapshot would report, without cloning the pattern's collections.
func TestPatternSummaryMatchesPattern(t *testing.T) {
	pt := NewPatternTracker(nil)
	ip := net.ParseIP("203.0.113.10")
	for i := range 7 {
		pt.RecordConnection(ip, ConnectionMetadata{PacketSize: 100, DestPort: uint16(80 + i)})
	}

	full := pt.GetPattern(ip)
	s, ok := pt.PatternSummary(ip)
	if !ok {
		t.Fatal("expected a summary")
	}
	if s.ConnectionAttempts != full.ConnectionAttempts {
		t.Fatalf("ConnectionAttempts = %d, want %d", s.ConnectionAttempts, full.ConnectionAttempts)
	}
	if s.PortsAccessed != len(full.PortsAccessed) {
		t.Fatalf("PortsAccessed = %d, want %d", s.PortsAccessed, len(full.PortsAccessed))
	}
	if s.PacketTimings != len(full.PacketTimings) {
		t.Fatalf("PacketTimings = %d, want %d", s.PacketTimings, len(full.PacketTimings))
	}
	if !s.FirstSeen.Equal(full.FirstSeen) {
		t.Fatalf("FirstSeen = %v, want %v", s.FirstSeen, full.FirstSeen)
	}

	if _, ok := pt.PatternSummary(net.ParseIP("198.51.100.1")); ok {
		t.Fatal("expected ok=false for an untracked IP")
	}
}
