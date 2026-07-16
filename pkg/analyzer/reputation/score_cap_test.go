package reputation

import (
	"math"
	"testing"
	"time"
)

// Per-IP and per-JA4 penalties must accumulate. The engine clamps each entry's
// score to a per-type cap; that cap must default to "uncapped" (like the ASN
// cap) so a penalty is not silently clamped back to zero. Regression test for
// the IP/JA4 caps defaulting to 0, which made all per-IP/JA4 reputation
// penalties no-ops in production.
func TestIPAndJA4PenaltiesAccumulate(t *testing.T) {
	e := New(time.Hour, 0.95, 1000) // high ban threshold; 1h decay so none within the test

	if got := e.Penalize("203.0.113.7", TypeIP, 20, "test"); got != 20 {
		t.Fatalf("IP penalty clamped: Penalize returned %v, want 20", got)
	}
	if got := e.GetScore("203.0.113.7", TypeIP); got != 20 {
		t.Fatalf("IP score did not accumulate: GetScore = %v, want 20", got)
	}

	if got := e.Penalize("t13d1516h2_abcd", TypeJA4, 15, "test"); got != 15 {
		t.Fatalf("JA4 penalty clamped: Penalize returned %v, want 15", got)
	}
	if got := e.GetScore("t13d1516h2_abcd", TypeJA4); got != 15 {
		t.Fatalf("JA4 score did not accumulate: GetScore = %v, want 15", got)
	}
}

// The default caps must be uncapped so operators who never call SetIPScoreCap /
// SetJA4ScoreCap still get accumulating scores, matching the ASN cap default.
func TestDefaultScoreCapsAreUncapped(t *testing.T) {
	e := New(time.Hour, 0.95, 1000)
	for _, tc := range []struct {
		name string
		cap  float64
	}{
		{"ip", e.getIPScoreCap()},
		{"ja4", e.getJA4ScoreCap()},
		{"asn", e.getASNScoreCap()},
	} {
		if !math.IsInf(tc.cap, 1) {
			t.Fatalf("%s score cap default = %v, want +Inf (uncapped)", tc.name, tc.cap)
		}
	}
}
