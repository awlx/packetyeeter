package aidetection

import "testing"

func TestBlendMLConfidenceKeepsRuleFloor(t *testing.T) {
	got := blendMLConfidence(0.92, MLPredictionResult{
		IsBot:          false,
		Confidence:     0.99,
		BotProbability: 0.01,
	})
	if got != 0.92 {
		t.Fatalf("expected strong rule confidence to remain the floor, got %.2f", got)
	}
}

func TestBlendMLConfidenceRaisesBotConfidence(t *testing.T) {
	got := blendMLConfidence(0.62, MLPredictionResult{
		IsBot:          true,
		Confidence:     0.87,
		BotProbability: 0.87,
	})
	if got != 0.87 {
		t.Fatalf("expected ML bot prediction to raise confidence, got %.2f", got)
	}
}

func TestBlendMLConfidenceOnlyLowersOnStrongLegitimate(t *testing.T) {
	weakLegitimate := blendMLConfidence(0.70, MLPredictionResult{
		IsBot:          false,
		Confidence:     0.55,
		BotProbability: 0.05,
	})
	if weakLegitimate != 0.70 {
		t.Fatalf("expected weak legitimate ML prediction not to lower confidence, got %.2f", weakLegitimate)
	}

	strongLegitimate := blendMLConfidence(0.70, MLPredictionResult{
		IsBot:          false,
		Confidence:     0.95,
		BotProbability: 0.03,
	})
	if strongLegitimate != legitimateMLConfidenceCap {
		t.Fatalf("expected strong legitimate ML prediction to cap confidence at %.2f, got %.2f", legitimateMLConfidenceCap, strongLegitimate)
	}
}
