package clockskew

import (
	"net"
	"testing"
	"time"
)

// TestProcessTimestamp_RejectsImplausibleSkew verifies that a skew
// computation far beyond any plausible real clock drift (as would happen if
// an IP profile actually represents multiple different hosts sharing one
// address behind CGNAT, not one host's clock genuinely drifting) resets the
// profile instead of being stored/reported. Before this fix, values in the
// hundreds of millions to billions of PPM were observed dominating
// production false-positive detections on large CGNAT'd consumer ISPs.
func TestProcessTimestamp_RejectsImplausibleSkew(t *testing.T) {
	a := NewAnalyzer(nil)
	ip := net.ParseIP("198.51.100.7")

	a.ProcessTimestamp(ip, 1000)

	a.mu.Lock()
	profile := a.profiles[ip.String()]
	profile.FirstObservedAt = time.Now().Add(-70 * time.Second)
	profile.LastObservedAt = time.Now().Add(-70 * time.Second)
	profile.Observations = 25
	a.mu.Unlock()

	// ~70s of real time should correspond to roughly 70000 TSval ticks at
	// the standard 1kHz TCP timestamp clock. A TSval delta of 500 million
	// implies an impossible clock rate, not real drift.
	a.ProcessTimestamp(ip, 1000+500_000_000)

	a.mu.RLock()
	profile = a.profiles[ip.String()]
	skew := profile.SkewPPM
	obs := profile.Observations
	a.mu.RUnlock()

	if skew != 0 {
		t.Fatalf("expected implausible skew to be rejected (SkewPPM reset to 0), got %v", skew)
	}
	if obs != 1 {
		t.Fatalf("expected profile to reset to 1 observation after rejecting an implausible skew value, got %d", obs)
	}
}

// TestProcessTimestamp_AcceptsPlausibleSkew is a regression guard ensuring
// the implausible-skew rejection doesn't also swallow genuine, modest clock
// drift.
func TestProcessTimestamp_AcceptsPlausibleSkew(t *testing.T) {
	a := NewAnalyzer(nil)
	ip := net.ParseIP("198.51.100.8")

	a.ProcessTimestamp(ip, 1000)

	a.mu.Lock()
	profile := a.profiles[ip.String()]
	profile.FirstObservedAt = time.Now().Add(-70 * time.Second)
	profile.LastObservedAt = time.Now().Add(-70 * time.Second)
	profile.Observations = 25
	a.mu.Unlock()

	// ~70s of real time -> ~70000 ticks expected. Use a TSval delta with a
	// modest ~200 PPM of drift, well within real-world clock behavior.
	a.ProcessTimestamp(ip, 1000+70014)

	a.mu.RLock()
	profile = a.profiles[ip.String()]
	skew := profile.SkewPPM
	obs := profile.Observations
	a.mu.RUnlock()

	if obs != 26 {
		t.Fatalf("expected profile to accumulate normally for a plausible skew value, got %d observations", obs)
	}
	if absFloat(skew) > maxPlausibleSkewPPM {
		t.Fatalf("test setup produced an implausible skew value %v ppm, adjust the test", skew)
	}
}

func absFloat(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
