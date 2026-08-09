package ml

import (
	"testing"

	"PacketYeeter/pkg/analyzer/aidetection"
)

func TestSimpleThresholdModelReportsStatisticalTier(t *testing.T) {
	model := NewSimpleThresholdModel()
	prediction := model.Predict(aidetection.MLFeatures{})

	if prediction.ModelTier != "statistical" {
		t.Fatalf("expected statistical model tier, got %q", prediction.ModelTier)
	}
}

func TestBehavioralScoreDoesNotPenalizePristineReputation(t *testing.T) {
	model := NewSimpleThresholdModel()
	pristine := model.calculateBehavioralScore(aidetection.MLFeatures{ReputationScore: 0})
	penalized := model.calculateBehavioralScore(aidetection.MLFeatures{ReputationScore: 100})

	if pristine != penalized {
		t.Fatalf("uncalibrated reputation changed behavioral score: pristine=%v penalized=%v", pristine, penalized)
	}
}

func TestStatisticalWeightsSumToOne(t *testing.T) {
	model := NewSimpleThresholdModel()
	sum := model.signalCountWeight + model.signalRateWeight + model.diversityWeight +
		model.temporalWeight + model.networkWeight + model.behavioralWeight +
		model.compositionWeight + model.threatIntelWeight
	if sum < 0.999 || sum > 1.001 {
		t.Fatalf("Predict weights sum to %v, want 1.0", sum)
	}
}

func TestNetworkScoreIgnoresMissingJA4HWithoutHTTPContext(t *testing.T) {
	model := NewSimpleThresholdModel()
	noHTTP := model.calculateNetworkScore(aidetection.MLFeatures{})
	withHTTP := model.calculateNetworkScore(aidetection.MLFeatures{UserAgent: "curl/8.0"})
	if noHTTP != 0 {
		t.Fatalf("transport-only missing JA4H score=%v, want 0", noHTTP)
	}
	if withHTTP < 0.4 {
		t.Fatalf("HTTP-context missing JA4H score=%v, want >= 0.4", withHTTP)
	}
}

func TestStrongSignalsCanCrossBotThreshold(t *testing.T) {
	model := NewSimpleThresholdModel()
	// High signal volume + known scanner should be able to cross 0.65 now that
	// weights sum to 1.0 (previously max mass was ~0.75 with much of it unused).
	pred := model.Predict(aidetection.MLFeatures{
		SignalCount:      40,
		SignalRate:       5,
		SignalDiversity:  8,
		IsKnownScanner:   true,
		ThreatScore:      80,
		IsBursty:         true,
		TimeOfDay:        3,
		TimeSpan:         10,
		DetectionHistory: 5,
		RequestRate:      20,
		HasASN:           true,
		UserAgent:        "scanner",
	})
	if !pred.IsBot {
		t.Fatalf("expected IsBot for strong scanner features, got p=%v", pred.BotProbability)
	}
}
