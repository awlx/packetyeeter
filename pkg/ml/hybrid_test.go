package ml

import (
	"testing"

	"PacketYeeter/pkg/analyzer/aidetection"
)

// fakePatternChecker lets tests control exactly what CheckPattern receives,
// so we can assert the hybrid model passes through the real UserAgent/ASN
// (GeoCountry)/JA4H from MLFeatures instead of the empty-string stubs that
// used to make the pattern-matching fast path structurally unreachable.
type fakePatternChecker struct {
	gotUserAgent, gotASN, gotJA4H string
	matched                       bool
	label                         string
	confidence                    float64
}

func (f *fakePatternChecker) CheckPattern(userAgent, asn, ja4h string) (bool, string, float64, string) {
	f.gotUserAgent = userAgent
	f.gotASN = asn
	f.gotJA4H = ja4h
	return f.matched, f.label, f.confidence, "test-key"
}

func TestHybridModelPredictPassesRealIdentifiersToPatternChecker(t *testing.T) {
	h := NewHybridModel("", 0.5)
	checker := &fakePatternChecker{}
	h.SetPatternChecker(checker)

	features := aidetection.MLFeatures{
		UserAgent:  "Mozilla/5.0 (compatible; ExampleBot/1.0)",
		GeoCountry: "AS12345",
		JA4H:       "ja4h_fake_fingerprint",
	}

	_ = h.Predict(features)

	if checker.gotUserAgent != features.UserAgent {
		t.Errorf("expected pattern checker to receive UserAgent %q, got %q", features.UserAgent, checker.gotUserAgent)
	}
	if checker.gotASN != features.GeoCountry {
		t.Errorf("expected pattern checker to receive ASN %q, got %q", features.GeoCountry, checker.gotASN)
	}
	if checker.gotJA4H != features.JA4H {
		t.Errorf("expected pattern checker to receive JA4H %q, got %q", features.JA4H, checker.gotJA4H)
	}
}

func TestHybridModelPredictUsesPatternMatchWhenFound(t *testing.T) {
	h := NewHybridModel("", 0.5)
	checker := &fakePatternChecker{matched: true, label: "malicious", confidence: 0.9}
	h.SetPatternChecker(checker)

	result := h.Predict(aidetection.MLFeatures{
		UserAgent: "curl/8.0",
		JA4H:      "abc123",
	})

	if result.ModelTier != "pattern" {
		t.Fatalf("expected model tier 'pattern', got %q", result.ModelTier)
	}
	if !result.IsBot {
		t.Fatalf("expected IsBot=true for malicious pattern match")
	}
}
