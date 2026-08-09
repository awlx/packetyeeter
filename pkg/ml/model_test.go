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
