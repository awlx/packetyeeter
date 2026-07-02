package aidetection

import "testing"

func TestCanonicalizeSignalType(t *testing.T) {
	cases := []struct {
		in   SignalType
		want SignalType
	}{
		{"LATENCY_ANOMALY", SignalLatencyAnomaly},
		{"latency_anomaly", SignalLatencyAnomaly},
		{"JA4H_BOT_MATCH", SignalJA4HBotMatch},
		{"user_agent_bot_keyword", SignalUserAgentBotKeyword},
		{"MISSING_ACCEPT_LANGUAGE", SignalMissingAcceptLang},
		{"KNOWN_SCANNER", SignalKnownScanner},
		{"path_seq_ids", SignalNumericSequence},
		{"numeric_seq", SignalNumericSequence},
		{"alpha_seq", SignalAlphaSequence},
		{"browser_detected", SignalBrowserDetected},
	}
	for _, tc := range cases {
		got := CanonicalizeSignalType(tc.in)
		if got != tc.want {
			t.Errorf("CanonicalizeSignalType(%q)=%q want %q", tc.in, got, tc.want)
		}
	}

	if got := CanonicalizeSignalType(SignalBotUA); got != SignalBotUA {
		t.Errorf("expected passthrough for SignalBotUA, got %q", got)
	}
}
