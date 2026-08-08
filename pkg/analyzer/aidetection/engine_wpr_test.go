package aidetection

import (
	"fmt"
	"testing"
	"time"

	"PacketYeeter/pkg/utils/ewma"
)

// Deterministic high-severity signals (honeypot, a confirmed known-bot *exact*
// JA4H match) must be recognized so a learned-legitimate allowlist match cannot
// suppress them and a strong-legitimate ML verdict cannot erase them. Anything
// weaker must NOT get deterministic status: a wildcard/coarse-prefix collision,
// a non-bot JA4DB entry, or an exact match on JA4/JA4T rather than the HTTP
// fingerprint - otherwise a legitimate client that merely collides on a prefix
// or fingerprint becomes unblockable.
func TestContainsDeterministicHighSeverity(t *testing.T) {
	if !containsDeterministicHighSeverity([]Signal{{Type: SignalHoneypot}}) {
		t.Error("honeypot must be high-severity")
	}

	exact := []Signal{
		{Type: SignalWindowAnomaly},
		{Type: SignalJA4HBotMatch, Metadata: map[string]interface{}{"known_bot": true, "fp_type": "ja4h", "match_type": "exact"}},
	}
	if !containsDeterministicHighSeverity(exact) {
		t.Error("confirmed known-bot exact JA4H match must be high-severity")
	}

	wildcard := []Signal{
		{Type: SignalJA4HBotMatch, Metadata: map[string]interface{}{"known_bot": true, "fp_type": "ja4h", "match_type": "wildcard_tls"}},
	}
	if containsDeterministicHighSeverity(wildcard) {
		t.Error("wildcard JA4H bot match must NOT be deterministic high-severity")
	}

	nonBot := []Signal{
		{Type: SignalJA4HBotMatch, Metadata: map[string]interface{}{"known_bot": false, "fp_type": "ja4h", "match_type": "exact"}},
	}
	if containsDeterministicHighSeverity(nonBot) {
		t.Error("a non-bot exact JA4H match must NOT be deterministic high-severity")
	}

	exactJA4 := []Signal{
		{Type: SignalJA4HBotMatch, Metadata: map[string]interface{}{"known_bot": true, "fp_type": "ja4", "match_type": "exact"}},
	}
	if containsDeterministicHighSeverity(exactJA4) {
		t.Error("an exact JA4 (not JA4H) match must NOT be deterministic high-severity")
	}

	exactJA4T := []Signal{
		{Type: SignalJA4HBotMatch, Metadata: map[string]interface{}{"known_bot": true, "fp_type": "ja4t", "match_type": "exact"}},
	}
	if containsDeterministicHighSeverity(exactJA4T) {
		t.Error("an exact JA4T (not JA4H) match must NOT be deterministic high-severity")
	}

	if containsDeterministicHighSeverity([]Signal{{Type: SignalJA4HBotMatch}}) {
		t.Error("JA4H bot match without metadata must NOT be deterministic high-severity")
	}
	if containsDeterministicHighSeverity([]Signal{{Type: SignalWindowAnomaly}, {Type: SignalNoCookies}}) {
		t.Error("low-severity-only signals must not be high-severity")
	}
	if containsDeterministicHighSeverity(nil) {
		t.Error("empty signals must not be high-severity")
	}
}

// The adaptive-detection map evicts the oldest entries when full instead of
// failing open, so a churn of distinct keys cannot silently disable it.
func TestEvictOldestEWMA(t *testing.T) {
	base := time.Now()
	m := map[string]*ewma.State{}
	for i := 0; i < 10; i++ {
		m[fmt.Sprintf("k%d", i)] = &ewma.State{LastTime: base.Add(time.Duration(i) * time.Second)}
	}
	evictOldestEWMA(m, 3)
	if len(m) != 7 {
		t.Fatalf("len = %d, want 7", len(m))
	}
	for i := 0; i < 3; i++ {
		if _, ok := m[fmt.Sprintf("k%d", i)]; ok {
			t.Fatalf("oldest key k%d survived eviction", i)
		}
	}
	// Evicting more than present is a no-op-safe clear-down.
	evictOldestEWMA(m, 100)
	if len(m) != 0 {
		t.Fatalf("len = %d, want 0 after over-eviction", len(m))
	}
}

// AccumulateLearningData bounds the per-IP unique-path set so a high-volume path
// spray cannot grow it without limit for the whole learning window.
func TestAccumulateLearningDataCapsUniquePaths(t *testing.T) {
	f := NewFeedbackLoop(FeedbackConfig{})
	const ip = "203.0.113.9"
	f.RecordTruePositive(ip, "AS64500", 0.9, BotCategoryScraper, true)

	for i := 0; i < maxLearningUniquePaths+500; i++ {
		f.AccumulateLearningData(ip, LearningData{Path: fmt.Sprintf("/p%d", i)})
	}

	f.mu.Lock()
	n := len(f.learningIPs[ip].UniquePaths)
	f.mu.Unlock()
	if n > maxLearningUniquePaths {
		t.Fatalf("UniquePaths grew to %d, want <= %d", n, maxLearningUniquePaths)
	}
	if n == 0 {
		t.Fatalf("expected the IP to be in the learning window with accumulated paths")
	}
}
