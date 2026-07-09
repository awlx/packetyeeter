package ml

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/analyzer/aidetection"
)

// HybridModel combines pattern matching with ML inference
// Decision flow:
//  1. Check learned patterns first (instant, high confidence)
//  2. If no pattern match, use ONNX model (for unknown patterns)
//  3. Fallback to statistical model if ONNX unavailable
type HybridModel struct {
	mu sync.RWMutex

	// Pattern checker (injected from feedback loop)
	patternChecker PatternChecker

	// ML models (in priority order)
	onnxModel        *ONNXModel
	statisticalModel *SimpleThresholdModel

	// Metrics
	patternMatches     uint64
	onnxInferences     uint64
	fallbackInferences uint64
	lastUpdate         time.Time
}

// PatternChecker interface for checking learned patterns
type PatternChecker interface {
	CheckPattern(userAgent, asn, ja4h string) (matched bool, label string, confidence float64, key string)
}

// NewHybridModel creates a hybrid model with ONNX + fallback
func NewHybridModel(onnxPath string, threshold float64) *HybridModel {
	h := &HybridModel{
		statisticalModel: NewSimpleThresholdModel(),
		lastUpdate:       time.Now(),
	}

	// Try to load ONNX model if path provided
	if onnxPath != "" {
		onnx, err := LoadONNXModel(onnxPath, threshold)
		if err != nil {
			logrus.WithError(err).Warn("Failed to load ONNX model, using statistical fallback only")
		} else {
			h.onnxModel = onnx
			logrus.WithField("model_path", onnxPath).Info("Hybrid model: ONNX loaded successfully")
		}
	}

	return h
}

// SetPatternChecker injects the pattern checker (from feedback loop)
func (h *HybridModel) SetPatternChecker(pc PatternChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.patternChecker = pc
	logrus.Info("Hybrid model: Pattern checker enabled")
}

// Predict implements intelligent routing:
// Pattern match → ONNX → Statistical fallback
func (h *HybridModel) Predict(features aidetection.MLFeatures) aidetection.MLPredictionResult {
	// Extract identifiers for pattern matching. UserAgent/JA4H come straight
	// from the detection's signals (see Engine.extractMLFeatures); ASN is
	// carried in GeoCountry, which extractMLFeatures populates with the
	// actual ASN string (no separate geo-country database is wired up).
	userAgent := features.UserAgent
	asn := features.GeoCountry
	ja4h := features.JA4H

	// 1. Check learned patterns first (fastest path)
	if h.patternChecker != nil {
		if matched, label, confidence, key := h.patternChecker.CheckPattern(userAgent, asn, ja4h); matched {
			h.mu.Lock()
			h.patternMatches++
			h.mu.Unlock()

			isBot := (label == "malicious")
			botProb := confidence
			if !isBot {
				botProb = 1.0 - confidence
			}

			category := inferCategoryFromLabel(label, features)

			logrus.WithFields(logrus.Fields{
				"pattern_key": key,
				"label":       label,
				"confidence":  confidence,
				"decision":    "pattern_match",
			}).Debug("Hybrid model: Pattern match - skipping ML inference")

			return aidetection.MLPredictionResult{
				IsBot:          isBot,
				BotProbability: botProb,
				Confidence:     confidence,
				Category:       category,
				ModelTier:      "pattern",
			}
		}
	}

	// 2. No pattern match - try ONNX for unknown patterns
	if h.onnxModel != nil {
		h.mu.Lock()
		h.onnxInferences++
		h.mu.Unlock()

		result := h.onnxModel.Predict(features)
		result.ModelTier = "onnx"

		logrus.WithFields(logrus.Fields{
			"bot_probability": result.BotProbability,
			"confidence":      result.Confidence,
			"decision":        "onnx_inference",
		}).Debug("Hybrid model: ONNX inference for unknown pattern")

		return result
	}

	// 3. Fallback to statistical model
	h.mu.Lock()
	h.fallbackInferences++
	h.mu.Unlock()

	logrus.Debug("Hybrid model: Using statistical fallback")
	result := h.statisticalModel.Predict(features)
	result.ModelTier = "statistical"
	return result
}

// Train updates the underlying models
func (h *HybridModel) Train(features aidetection.MLFeatures, isBot bool) error {
	// Only train statistical model (ONNX is static)
	if h.statisticalModel != nil {
		return h.statisticalModel.Train(features, isBot)
	}
	return nil
}

// GetMetrics returns hybrid model metrics
func (h *HybridModel) GetMetrics() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	total := h.patternMatches + h.onnxInferences + h.fallbackInferences
	patternPct := float64(0)
	onnxPct := float64(0)
	fallbackPct := float64(0)

	if total > 0 {
		patternPct = float64(h.patternMatches) / float64(total) * 100
		onnxPct = float64(h.onnxInferences) / float64(total) * 100
		fallbackPct = float64(h.fallbackInferences) / float64(total) * 100
	}

	return map[string]interface{}{
		"pattern_matches":     h.patternMatches,
		"onnx_inferences":     h.onnxInferences,
		"fallback_inferences": h.fallbackInferences,
		"total_predictions":   total,
		"pattern_match_pct":   patternPct,
		"onnx_usage_pct":      onnxPct,
		"fallback_usage_pct":  fallbackPct,
		"has_onnx":            h.onnxModel != nil,
		"has_pattern_checker": h.patternChecker != nil,
	}
}

// Close releases resources
func (h *HybridModel) Close() error {
	if h.onnxModel != nil {
		return h.onnxModel.Close()
	}
	return nil
}

// Helper functions

func inferCategoryFromLabel(label string, features aidetection.MLFeatures) aidetection.BotCategory {
	if label == "legitimate" {
		return aidetection.BotCategoryUnknown
	}

	// Use signal types to infer category for malicious traffic
	if features.SignalTypeVector[aidetection.SignalPortScanning] > 3 {
		return aidetection.BotCategoryScanner
	}

	ddosSignals := features.SignalTypeVector[aidetection.SignalICMPFlood] +
		features.SignalTypeVector[aidetection.SignalUDPFlood] +
		features.SignalTypeVector[aidetection.SignalSYNFlood]
	if ddosSignals > 10 {
		return aidetection.BotCategoryDDoS
	}

	if features.SignalTypeVector[aidetection.SignalPathSeqIDs] > 5 ||
		features.SignalTypeVector[aidetection.SignalPathEntropyLow] > 5 {
		return aidetection.BotCategoryScraper
	}

	return aidetection.BotCategoryMalicious
}
