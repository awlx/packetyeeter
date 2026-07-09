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
