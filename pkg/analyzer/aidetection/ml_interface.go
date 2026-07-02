package aidetection

// MLModel is the interface for machine learning bot detection models
type MLModel interface {
	// Predict returns a prediction for the given features
	Predict(features MLFeatures) MLPredictionResult

	// Train updates the model with new labeled data (for online learning)
	Train(features MLFeatures, isBot bool) error
}

// MLPredictionResult contains the ML model's prediction
type MLPredictionResult struct {
	IsBot          bool        // Whether the model predicts this is a bot
	Confidence     float64     // Confidence in the prediction (0-1)
	BotProbability float64     // Probability of being a bot (0-1)
	Category       BotCategory // Predicted bot category
	ModelTier      string      // Which model tier made prediction: "pattern", "onnx", "statistical"
}
