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

// Auto-detected model sizes from LoadONNXModel's probe list (onnx.go
// loadONNXModelInternal): 126, 116, 110, 106, 100, 144, 41, 50. Sizes
// 100/106/110 previously panicked in featuresToTensorAdvanced because it
// wrote fixed offsets up to index 115 unconditionally regardless of the
// allocated tensor length (W22).
func TestFeaturesToTensorAdvanced_NoPanicOnAutoDetectedSizes(t *testing.T) {
	sizes := []int{100, 106, 110, 116, 126, 144}
	features := sampleFeaturesWithHistory()

	for _, size := range sizes {
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
				t.Fatalf("featuresToTensor(nFeatures=%d) returned tensor of length %d, want %d", size, len(tensor), size)
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
