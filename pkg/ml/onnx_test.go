package ml

import (
	"testing"
	"time"

	"PacketYeeter/pkg/analyzer/aidetection"
)

// sampleFeaturesWithHistory builds an MLFeatures with a populated EventHistory
// so featuresToTensor routes into featuresToTensorAdvanced (requires
// nFeatures>=100 && EventHistory!=nil, see onnx.go featuresToTensor).
func sampleFeaturesWithHistory() aidetection.MLFeatures {
	now := time.Now()
	return aidetection.MLFeatures{
		SignalCount:    3,
		SignalRate:     1.5,
		Confidence:     0.9,
		ThreatScore:    42,
		JA4:            "t13d1516h2_8daaf6152771_02713d6af862",
		JA4H:           "ge11nn020000_9ed1ff1f7e77",
		JA4T:           "64240_2-1-3-1-1-4_1460_8",
		WouldBlock:     true,
		PathCount:      2,
		UserAgentCount: 1,
		ASN:            64512,
		AsnReputation:  0.5,
		EventHistory: &aidetection.EventHistorySnapshot{
			Events: []aidetection.SignalEvent{
				{Type: aidetection.SignalHighFrequency, Source: aidetection.SourceSPOE, Timestamp: now},
			},
			Paths:       []string{"/", "/login"},
			UserAgents:  []string{"curl/8.0"},
			Methods:     []string{"GET"},
			Referers:    []string{""},
			AcceptLangs: []string{"en-US"},
			Timestamps:  []time.Time{now},
		},
	}
}

// The 126-feature layout is the full advanced layout documented in
// docs/advanced_features.md / scripts/extract_advanced_features.py. The
// detection block occupies indices [115:126]; verify each index carries the
// exact meaning the training/export contract assigns to it, not merely that the
// tensor has the right length.
func TestFeaturesToTensorAdvanced_126IndexSemantics(t *testing.T) {
	features := sampleFeaturesWithHistory()
	m := &ONNXModel{nFeatures: 126}
	tensor := m.featuresToTensor(features)

	if len(tensor) != 126 {
		t.Fatalf("tensor length = %d, want 126", len(tensor))
	}

	checks := []struct {
		idx  int
		want float32
		name string
	}{
		{115, float32(features.Confidence), "confidence"},
		{116, float32(features.SignalCount), "signal_count"},
		{117, 1.0, "would_block"},
		{118, float32(features.ThreatScore), "threat_score"},
		{119, 1.0, "has_ja4"},
		{120, 1.0, "has_ja4h"},
		{121, 1.0, "has_ja4t"},
		{122, float32(features.PathCount), "path_count"},
		{123, float32(features.UserAgentCount), "user_agent_count"},
		{124, float32(features.ASN), "asn"},
		{125, float32(features.AsnReputation), "asn_reputation"},
	}
	for _, c := range checks {
		if tensor[c.idx] != c.want {
			t.Errorf("tensor[%d] (%s) = %v, want %v", c.idx, c.name, tensor[c.idx], c.want)
		}
	}
}

// A model with no JA4/JA4T fingerprints must leave the corresponding presence
// flags at 0. This guards against an index being wired to the wrong source.
func TestFeaturesToTensorAdvanced_126SentinelZeroFlags(t *testing.T) {
	features := sampleFeaturesWithHistory()
	features.JA4 = ""
	features.JA4T = ""
	features.WouldBlock = false
	m := &ONNXModel{nFeatures: 126}
	tensor := m.featuresToTensor(features)

	if tensor[117] != 0 {
		t.Errorf("tensor[117] (would_block) = %v, want 0", tensor[117])
	}
	if tensor[119] != 0 {
		t.Errorf("tensor[119] (has_ja4) = %v, want 0", tensor[119])
	}
	if tensor[121] != 0 {
		t.Errorf("tensor[121] (has_ja4t) = %v, want 0", tensor[121])
	}
	// JA4H is still set, so its flag must remain 1.
	if tensor[120] != 1 {
		t.Errorf("tensor[120] (has_ja4h) = %v, want 1", tensor[120])
	}
}

// The 116-feature layout overlays the detection block at [95:100] (no
// fingerprint block). Verify those index semantics explicitly.
func TestFeaturesToTensorAdvanced_116IndexSemantics(t *testing.T) {
	features := sampleFeaturesWithHistory()
	m := &ONNXModel{nFeatures: 116}
	tensor := m.featuresToTensor(features)

	if len(tensor) != 116 {
		t.Fatalf("tensor length = %d, want 116", len(tensor))
	}
	if tensor[95] != float32(features.Confidence) {
		t.Errorf("tensor[95] (confidence) = %v, want %v", tensor[95], float32(features.Confidence))
	}
	if tensor[96] != float32(features.SignalCount) {
		t.Errorf("tensor[96] (signal_count) = %v, want %v", tensor[96], float32(features.SignalCount))
	}
	if tensor[97] != 1.0 {
		t.Errorf("tensor[97] (would_block) = %v, want 1", tensor[97])
	}
	if tensor[98] != float32(features.ThreatScore) {
		t.Errorf("tensor[98] (threat_score) = %v, want %v", tensor[98], float32(features.ThreatScore))
	}
}

// Unsupported widths (100/106/110/144) have no defined layout. LoadONNXModel
// rejects them; the extraction helper is defensive and must return an all-zero
// tensor of the requested length rather than a truncated/misaligned one or a
// panic, so a bug that reaches it fails observably and enforcement-safe.
func TestFeaturesToTensorAdvanced_UnsupportedWidthZeroed(t *testing.T) {
	features := sampleFeaturesWithHistory()
	for _, size := range []int{100, 106, 110, 144} {
		size := size
		t.Run(sizeLabel(size), func(t *testing.T) {
			m := &ONNXModel{nFeatures: size}
			var tensor []float32
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("featuresToTensor panicked for nFeatures=%d: %v", size, r)
					}
				}()
				tensor = m.featuresToTensor(features)
			}()
			if len(tensor) != size {
				t.Fatalf("tensor length = %d, want %d", len(tensor), size)
			}
			for i, v := range tensor {
				if v != 0 {
					t.Fatalf("unsupported width %d: tensor[%d] = %v, want all zeros", size, i, v)
				}
			}
		})
	}
}

func sizeLabel(n int) string {
	switch n {
	case 100:
		return "100"
	case 106:
		return "106"
	case 110:
		return "110"
	case 116:
		return "116"
	case 126:
		return "126"
	case 144:
		return "144"
	default:
		return "unknown"
	}
}
