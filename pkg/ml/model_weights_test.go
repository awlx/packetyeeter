package ml

import (
	"math"
	"testing"

	"PacketYeeter/pkg/analyzer/aidetection"
)

// hostileFeatures is a maximally bot-like entity: every signal group is pegged.
func hostileFeatures() aidetection.MLFeatures {
	return aidetection.MLFeatures{
		SignalCount:        100000,
		SignalDiversity:    100,
		SignalRate:         100000,
		ReputationScore:    20000,
		HasASN:             true,
		IsBursty:           true,
		TimeOfDay:          3,
		TimeSpan:           1,
		RequestRate:        10000,
		DetectionHistory:   100,
		ThreatScore:        100,
		IsKnownScanner:     true,
		IsTor:              true,
		IsVPN:              true,
		IsCloud:            true,
		HasVulnerabilities: true,
		OpenPortCount:      100,
		SignalTypeVector: map[aidetection.SignalType]int{
			aidetection.SignalPortScanning:        10,
			aidetection.SignalIncompleteHandshake: 10,
			aidetection.SignalJA4TAbuse:           10,
			aidetection.SignalTimingPattern:       10,
			aidetection.SignalGeoAnomaly:          10,
		},
		SourceVector: map[aidetection.SignalSource]int{
			aidetection.SourceTCP:  10,
			aidetection.SourceSPOE: 10,
			aidetection.SourceUDP:  10,
		},
	}
}

// A maximally hostile entity must be classifiable as a bot. Before every
// declared weight was applied in Predict, signalRateWeight (0.15) and
// diversityWeight (0.10) were stranded, capping the achievable confidence at
// 0.61 - below botThreshold (0.65) - so IsBot was false for every possible
// input and the ML gate rejected 100% of blocks.
func TestHostileEntityIsClassifiedAsBot(t *testing.T) {
	m := NewSimpleThresholdModel()
	p := m.Predict(hostileFeatures())

	if !p.IsBot {
		t.Fatalf("maximally hostile entity not classified as bot (confidence %.4f, threshold %.2f)",
			p.Confidence, m.botThreshold)
	}
	if p.Confidence <= 0.9 {
		t.Errorf("expected near-saturated confidence for hostile entity, got %.4f", p.Confidence)
	}
}

// The declared weights must sum to 1.0 and all of them must be reachable,
// otherwise the model cannot span the full 0-1 probability range.
func TestWeightsSumToOneAndAreAllApplied(t *testing.T) {
	m := NewSimpleThresholdModel()

	sum := m.signalCountWeight + m.signalRateWeight + m.diversityWeight +
		m.temporalWeight + m.networkWeight + m.behavioralWeight +
		m.compositionWeight + m.threatIntelWeight
	if math.Abs(sum-1.0) > 1e-9 {
		t.Fatalf("declared weights sum to %.4f, want 1.0", sum)
	}

	// Zeroing any single weight must move the hostile-entity prediction,
	// proving that weight is actually referenced by Predict.
	base := m.Predict(hostileFeatures()).Confidence

	for _, tc := range []struct {
		name string
		w    *float64
	}{
		{"signalCountWeight", &m.signalCountWeight},
		{"signalRateWeight", &m.signalRateWeight},
		{"diversityWeight", &m.diversityWeight},
		{"temporalWeight", &m.temporalWeight},
		{"networkWeight", &m.networkWeight},
		{"behavioralWeight", &m.behavioralWeight},
		{"compositionWeight", &m.compositionWeight},
		{"threatIntelWeight", &m.threatIntelWeight},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := *tc.w
			*tc.w = 0
			got := m.Predict(hostileFeatures()).Confidence
			*tc.w = orig

			if math.Abs(got-base) < 1e-9 {
				t.Errorf("%s is declared but never applied in Predict: zeroing it left confidence at %.4f", tc.name, got)
			}
		})
	}
}

// ReputationScore is the raw unbounded engine score (higher = worse), not a
// normalized 0-1 trust value. A bad-reputation entity must score higher than a
// pristine one; the old `ReputationScore < 0.3` test inverted this.
func TestBehavioralScoreTreatsHighReputationAsWorse(t *testing.T) {
	m := NewSimpleThresholdModel()

	pristine := m.calculateBehavioralScore(aidetection.MLFeatures{ReputationScore: 0})
	bad := m.calculateBehavioralScore(aidetection.MLFeatures{ReputationScore: 20000})

	if bad <= pristine {
		t.Fatalf("high reputation penalty scored %.4f, not greater than pristine %.4f", bad, pristine)
	}
	if bad > 1.0 {
		t.Errorf("behavioral score %.4f exceeds 1.0; normalization is unbounded", bad)
	}
}

// A benign entity must stay well clear of the bot threshold.
func TestBenignEntityIsNotClassifiedAsBot(t *testing.T) {
	m := NewSimpleThresholdModel()
	p := m.Predict(aidetection.MLFeatures{
		SignalCount:     1,
		SignalDiversity: 1,
		SignalRate:      0.1,
		ReputationScore: 0,
		HasASN:          true,
		HasJA4H:         true,
		TimeOfDay:       14,
		RequestRate:     0.5,
	})

	if p.IsBot {
		t.Fatalf("benign entity classified as bot (confidence %.4f)", p.Confidence)
	}
}
