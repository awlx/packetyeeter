package analyzer

import (
	"net"
	"testing"
	"time"
)

// TestUpdatePathEntropyDetectsRegularTiming verifies the new inter-request
// timing-regularity check: a script hitting the server on a near-perfectly
// fixed interval should be flagged, while normal human-paced (irregular)
// request gaps should not.
func TestUpdatePathEntropyDetectsRegularTiming(t *testing.T) {
	a := &Analyzer{pathWindows: make(map[string]*pathWindow)}
	ip := net.ParseIP("203.0.113.9")

	key := ip.String()
	// Seed events in the past so the natural progression to "now" (added by
	// the actual updatePathEntropy call below) preserves the ~500ms cadence.
	base := time.Now().Add(-7 * 500 * time.Millisecond)
	pw := &pathWindow{Counts: make(map[string]int)}
	for i := 0; i < 7; i++ {
		pw.Events = append(pw.Events, pathEvent{Path: "/poll", Ts: base.Add(time.Duration(i) * 500 * time.Millisecond)})
		pw.Counts["/poll"]++
		pw.Total++
	}
	a.pathWindows[key] = pw

	// The 8th request (triggering the check) arrives exactly on cadence.
	_, _, _, _, _, timingRegular := a.updatePathEntropy(ip, "/poll")
	if !timingRegular {
		t.Fatal("expected metronomic request cadence to be flagged as timing-regular")
	}
}

func TestUpdatePathEntropyIgnoresIrregularHumanTiming(t *testing.T) {
	a := &Analyzer{pathWindows: make(map[string]*pathWindow)}
	ip := net.ParseIP("203.0.113.10")
	key := ip.String()
	base := time.Now()

	// Irregular gaps: 0.3s, 4s, 1.2s, 8s, 0.5s, 2.7s, 6s - human-like.
	gaps := []time.Duration{
		300 * time.Millisecond, 4 * time.Second, 1200 * time.Millisecond,
		8 * time.Second, 500 * time.Millisecond, 2700 * time.Millisecond, 6 * time.Second,
	}
	pw := &pathWindow{Counts: make(map[string]int)}
	ts := base
	for _, g := range gaps {
		ts = ts.Add(g)
		pw.Events = append(pw.Events, pathEvent{Path: "/page", Ts: ts})
		pw.Counts["/page"]++
		pw.Total++
	}
	a.pathWindows[key] = pw

	_, _, _, _, _, timingRegular := a.updatePathEntropy(ip, "/page")
	if timingRegular {
		t.Fatal("expected irregular human-like request cadence to NOT be flagged as timing-regular")
	}
}

// TestCheckJA4ConsistencyTracksDistinctFingerprints verifies rotation
// detection: the same IP presenting several distinct JA4/JA4H fingerprints
// within the tracking window should be counted, enabling the caller to flag
// fingerprint rotation from a supposedly single-browser client.
func TestCheckJA4ConsistencyTracksDistinctFingerprints(t *testing.T) {
	a := &Analyzer{pathWindows: make(map[string]*pathWindow)}
	ip := net.ParseIP("203.0.113.11")

	ja4Count, ja4hCount := a.checkJA4Consistency(ip, "ja4-a", "ja4h-a")
	if ja4Count != 1 || ja4hCount != 1 {
		t.Fatalf("expected 1/1 after first observation, got %d/%d", ja4Count, ja4hCount)
	}

	// Same fingerprint again: counts should not increase.
	ja4Count, ja4hCount = a.checkJA4Consistency(ip, "ja4-a", "ja4h-a")
	if ja4Count != 1 || ja4hCount != 1 {
		t.Fatalf("expected counts to stay at 1/1 for repeated fingerprint, got %d/%d", ja4Count, ja4hCount)
	}

	// Distinct fingerprints: counts should grow.
	a.checkJA4Consistency(ip, "ja4-b", "ja4h-b")
	ja4Count, ja4hCount = a.checkJA4Consistency(ip, "ja4-c", "ja4h-c")
	if ja4Count != 3 || ja4hCount != 3 {
		t.Fatalf("expected 3/3 distinct fingerprints, got %d/%d", ja4Count, ja4hCount)
	}
}
