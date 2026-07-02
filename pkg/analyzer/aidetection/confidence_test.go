package aidetection

import (
	"strings"
	"testing"
)

func TestGenerateBlockReasonUsesThreshold(t *testing.T) {
	signals := map[SignalType]int{SignalTTLAnomaly: 1, SignalWindowAnomaly: 1}
	sources := map[SignalSource]int{}
	reason := GenerateBlockReason(signals, sources, BotCategoryUnknown, VerificationUnknown, 0.84, 0.70, 0.90, 0.25)
	if !strings.Contains(reason, "84") {
		t.Fatalf("expected confidence in reason, got %q", reason)
	}
	if !strings.Contains(reason, "70") {
		t.Fatalf("expected threshold in reason, got %q", reason)
	}
	if !strings.Contains(reason, "ttl_anomaly") {
		t.Fatalf("expected signal name in reason, got %q", reason)
	}
}
func TestInferCategoryFromSignals(t *testing.T) {
	cases := []struct {
		name   string
		sigs   map[SignalType]int
		expect BotCategory
	}{
		{"ddos", map[SignalType]int{SignalICMPFlood: 5}, BotCategoryDDoS},
		{"scanner", map[SignalType]int{SignalKnownScanner: 1}, BotCategoryScanner},
		{"malicious_fingerprint", map[SignalType]int{SignalJA4HBotMatch: 1}, BotCategoryMalicious},
		{"fallback_nonempty", map[SignalType]int{SignalHeaderOrderAnomaly: 1}, BotCategoryMalicious},
		{"empty", map[SignalType]int{}, BotCategoryUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InferCategoryFromSignals(tc.sigs); got != tc.expect {
				t.Fatalf("expected %s got %s", tc.expect, got)
			}
		})
	}
}
