package aidetection

import (
	"net"
	"testing"
)

// TestExtractMLFeaturesPopulatesRawIdentifiers ensures the engine's
// extractMLFeatures threads through the raw UserAgent/JA4/JA4H/JA4T
// identifiers needed by the hybrid model's pattern-matching fast path and
// the ONNX fingerprint feature extractor - these used to be silently
// dropped (always empty), which made pattern matching structurally
// unreachable regardless of how many patterns were learned.
func TestExtractMLFeaturesPopulatesRawIdentifiers(t *testing.T) {
	e := New(DefaultConfig())

	signals := []Signal{
		{
			Type: SignalBotUA,
			IP:   net.ParseIP("203.0.113.5"),
			ASN:  "AS64500",
			JA4:  "ja4_value",
			JA4H: "ja4h_value",
			JA4T: "ja4t_value",
			Metadata: map[string]interface{}{
				"user_agent": "curl/8.0",
			},
		},
	}
	signalTypes := map[SignalType]int{SignalBotUA: 1}
	sources := map[SignalSource]int{SourceSPOE: 1}

	features := e.extractMLFeatures(signals, signalTypes, sources, nil, 0)

	if features.UserAgent != "curl/8.0" {
		t.Errorf("expected UserAgent %q, got %q", "curl/8.0", features.UserAgent)
	}
	if features.JA4 != "ja4_value" {
		t.Errorf("expected JA4 %q, got %q", "ja4_value", features.JA4)
	}
	if features.JA4H != "ja4h_value" {
		t.Errorf("expected JA4H %q, got %q", "ja4h_value", features.JA4H)
	}
	if features.JA4T != "ja4t_value" {
		t.Errorf("expected JA4T %q, got %q", "ja4t_value", features.JA4T)
	}
	if features.GeoCountry != "AS64500" {
		t.Errorf("expected GeoCountry (ASN proxy) %q, got %q", "AS64500", features.GeoCountry)
	}
}
