package patterns

import (
	"net"
	"testing"
	"time"
)

// TestRecordConnection_PopulatesInterConnectionTiming is a regression test
// for a dead-code bug: PacketTimings was appended only inside
// `if len(pattern.PacketTimings) > 0`, so it could never bootstrap, and even
// if seeded the timing was measured against a LastSeen the same call had
// just overwritten to "now" (yielding ~0). Both defects together meant
// detectMechanicalTiming and the IsBursty ML feature were permanently fed
// zero data. This verifies a second connection now records a real,
// positive gap since the first, and the first connection - with nothing to
// diff against yet - records nothing.
func TestRecordConnection_PopulatesInterConnectionTiming(t *testing.T) {
	pt := NewPatternTracker(nil)
	ip := net.ParseIP("203.0.113.5")

	pt.RecordConnection(ip, ConnectionMetadata{TTL: 64})
	if p := pt.GetPattern(ip); len(p.PacketTimings) != 0 {
		t.Fatalf("expected no timing sample after the first connection (nothing to diff against yet), got %d", len(p.PacketTimings))
	}

	time.Sleep(5 * time.Millisecond)
	pt.RecordConnection(ip, ConnectionMetadata{TTL: 64})

	p := pt.GetPattern(ip)
	if len(p.PacketTimings) != 1 {
		t.Fatalf("expected one inter-connection timing sample after the second connection, got %d", len(p.PacketTimings))
	}
	if p.PacketTimings[0] <= 0 {
		t.Fatalf("expected a positive inter-connection delta, got %v", p.PacketTimings[0])
	}
}

// TestRecordConnection_TimingCapRespected verifies the existing 100-sample
// cap on PacketTimings still applies once the slice actually accumulates
// data (previously untestable, since the slice never grew at all).
func TestRecordConnection_TimingCapRespected(t *testing.T) {
	pt := NewPatternTracker(nil)
	ip := net.ParseIP("203.0.113.6")

	for i := 0; i < 105; i++ {
		pt.RecordConnection(ip, ConnectionMetadata{TTL: 64})
	}

	p := pt.GetPattern(ip)
	if len(p.PacketTimings) > 100 {
		t.Fatalf("expected PacketTimings to be capped at 100 entries, got %d", len(p.PacketTimings))
	}
	if len(p.PacketTimings) == 0 {
		t.Fatalf("expected PacketTimings to be populated after 105 connections")
	}
}

// TestDetectWindowAnomaly_StableRealisticWindowIsNotFlagged verifies that a
// single source consistently advertising the same, plausible TCP window
// size is NOT treated as anomalous. This is normal behavior for a real TCP
// stack (the value comes from that client's OS/socket-buffer configuration
// and won't change unless receive-buffer usage does) - production traffic
// showed ordinary VPS/hosting-provider clients getting false-positive
// flagged here purely because their stable window value wasn't in a
// hardcoded three-item allowlist.
func TestDetectWindowAnomaly_StableRealisticWindowIsNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := make([]uint16, 10)
	for i := range windows {
		windows[i] = 25765 // a real, if uncommon, window value seen in production
	}

	if pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected a stable, plausible window size to not be flagged as anomalous")
	}
}

// TestDetectWindowAnomaly_KnownCommonValuesNotFlagged is a regression guard
// for the previously-hardcoded allowlist values.
func TestDetectWindowAnomaly_KnownCommonValuesNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	for _, v := range []uint16{65535, 29200, 14600} {
		windows := make([]uint16, 10)
		for i := range windows {
			windows[i] = v
		}
		if pt.detectWindowAnomaly(windows) {
			t.Fatalf("expected common window value %d to not be flagged as anomalous", v)
		}
	}
}

// TestDetectWindowAnomaly_ZeroWindowIsFlagged verifies a stalled/malformed
// connection (window size 0 on every packet) is still caught.
func TestDetectWindowAnomaly_ZeroWindowIsFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := make([]uint16, 10) // all zero value
	if !pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected an all-zero window size to be flagged as anomalous")
	}
}

// TestDetectWindowAnomaly_TinyWindowIsFlagged verifies a suspiciously small
// stable window (characteristic of bare raw-socket scanning tools) is
// still caught.
func TestDetectWindowAnomaly_TinyWindowIsFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := make([]uint16, 10)
	for i := range windows {
		windows[i] = 64 // far below any real OS network stack default
	}
	if !pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected a tiny stable window size to be flagged as anomalous")
	}
}

// TestDetectWindowAnomaly_VaryingWindowsNotFlagged verifies windows that
// vary naturally (e.g. due to window scaling and changing receive-buffer
// occupancy) are not flagged just because they're not identical.
func TestDetectWindowAnomaly_VaryingWindowsNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := []uint16{25765, 25760, 25770, 25765, 25700, 25765, 25765, 25765, 25765, 25710}
	if pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected naturally varying window sizes to not be flagged as anomalous")
	}
}

// TestDetectWindowAnomaly_TooFewSamplesNotFlagged verifies the function
// requires at least 10 samples before making a determination.
func TestDetectWindowAnomaly_TooFewSamplesNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	windows := []uint16{0, 0, 0, 0, 0} // all-zero but too few samples
	if pt.detectWindowAnomaly(windows) {
		t.Fatalf("expected fewer than 10 samples to never be flagged")
	}
}

// TestDetectTTLAnomaly_TightAnycastJitterNotFlagged verifies natural TTL
// jitter from anycast/ECMP path diversity (production traffic from Meta's
// crawler infrastructure showed TTLs clustered in the low-to-mid 40s,
// varying by only a handful of hops) is not flagged as spoofing/proxying.
func TestDetectTTLAnomaly_TightAnycastJitterNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	ttls := []uint8{45, 45, 45, 47, 45, 45, 45, 45, 41, 47}
	if pt.detectTTLAnomaly(ttls) {
		t.Fatalf("expected tight anycast-style TTL jitter to not be flagged as anomalous")
	}
}

// TestDetectTTLAnomaly_SingleGlitchNotFlagged verifies a single malformed
// or glitched packet does not condemn an otherwise consistent window.
func TestDetectTTLAnomaly_SingleGlitchNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	ttls := []uint8{45, 45, 45, 47, 45, 45, 45, 45, 41, 236}
	if pt.detectTTLAnomaly(ttls) {
		t.Fatalf("expected a single outlier sample to not be flagged as anomalous")
	}
}

// TestDetectTTLAnomaly_RepeatedLargeJumpsFlagged verifies genuine, repeated
// large TTL swings with mismatched implied hop counts (i.e. not explained by
// two OS/network-gear default initial TTLs reaching the same real hop
// distance) are still caught as anomalous.
func TestDetectTTLAnomaly_RepeatedLargeJumpsFlagged(t *testing.T) {
	pt := &PatternTracker{}
	// mode=40 implies ~24 hops (base 64); 190 implies ~65 hops (base 255) -
	// wildly different real hop counts, not explainable by a shared path.
	ttls := []uint8{40, 40, 40, 190, 40, 40, 190, 40, 40, 40}
	if !pt.detectTTLAnomaly(ttls) {
		t.Fatalf("expected repeated large TTL jumps with mismatched hop counts to be flagged as anomalous")
	}
}

// TestDetectTTLAnomaly_OSFamilyPairNotFlagged verifies a TTL pair that is
// fully explained by two different OS/network-gear default initial TTLs
// (64, 128, 255) reaching the same real hop distance is not flagged. This
// matches a real production pattern seen at scale on Vodafone Germany's
// network: dozens of unrelated customer IPs each showed a TTL pair
// differing by exactly 191 (255-64) with matching implied hop counts,
// consistent with a CGNAT/NAT64 boundary or dual-stack gateway
// re-originating some packets - not spoofing.
func TestDetectTTLAnomaly_OSFamilyPairNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	// mode=50 implies 14 hops (base 64); 241 implies 14 hops (base 255) -
	// same real hop distance under a different OS TTL family.
	ttls := []uint8{50, 50, 241, 50, 241, 241, 50, 241, 50, 50}
	if pt.detectTTLAnomaly(ttls) {
		t.Fatalf("expected an OS-family-matched TTL pair to not be flagged as anomalous")
	}
}

// TestDetectTTLAnomaly_TooFewSamplesNotFlagged verifies the function
// requires at least 10 samples before making a determination.
func TestDetectTTLAnomaly_TooFewSamplesNotFlagged(t *testing.T) {
	pt := &PatternTracker{}
	ttls := []uint8{64, 64, 64, 128, 128}
	if pt.detectTTLAnomaly(ttls) {
		t.Fatalf("expected fewer than 10 samples to never be flagged")
	}
}
