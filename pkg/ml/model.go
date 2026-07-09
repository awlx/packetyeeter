package ml

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/analyzer/aidetection"
)

// ModelType represents the type of ML model
type ModelType string

const (
	ModelLogisticRegression ModelType = "logistic_regression"
	ModelRandomForest       ModelType = "random_forest"
	ModelNeuralNetwork      ModelType = "neural_network"
	ModelEnsemble           ModelType = "ensemble"
)

// PredictionResult contains the model's prediction and confidence
type PredictionResult struct {
	IsBot          bool
	Confidence     float64
	BotProbability float64
	Category       aidetection.BotCategory
	Features       aidetection.MLFeatures
	Timestamp      time.Time
}

// SimpleThresholdModel is a basic threshold-based classifier
type SimpleThresholdModel struct {
	mu sync.RWMutex

	// Thresholds
	botThreshold      float64
	highConfThreshold float64
	signalCountWeight float64
	signalRateWeight  float64
	diversityWeight   float64
	temporalWeight    float64
	networkWeight     float64
	behavioralWeight  float64
	compositionWeight float64
	threatIntelWeight float64

	// Learned parameters (for adaptive thresholding)
	meanSignalCount  float64
	stdSignalCount   float64
	meanSignalRate   float64
	stdSignalRate    float64
	observationCount uint64
	lastUpdate       time.Time

	// Persistence
	persistencePath string
}

// NewSimpleThresholdModel creates a new threshold-based model
func NewSimpleThresholdModel() *SimpleThresholdModel {
	m := &SimpleThresholdModel{
		botThreshold:      0.65,
		highConfThreshold: 0.85,
		signalCountWeight: 0.18,
		signalRateWeight:  0.15,
		diversityWeight:   0.10,
		temporalWeight:    0.08,
		networkWeight:     0.12,
		behavioralWeight:  0.12,
		compositionWeight: 0.08,
		threatIntelWeight: 0.17, // High weight for threat intel
		meanSignalCount:   5.0,
		stdSignalCount:    3.0,
		meanSignalRate:    0.5,
		stdSignalRate:     0.3,
		lastUpdate:        time.Now(),
		persistencePath:   "/var/lib/packetyeeter/ml_model_state.json",
	}

	// Try to load saved state
	if err := m.Load(); err != nil {
		if !os.IsNotExist(err) {
			logrus.WithError(err).Warn("Failed to load ML model state, using defaults")
		}
	} else {
		logrus.WithFields(logrus.Fields{
			"observations": m.observationCount,
			"last_update":  m.lastUpdate,
		}).Info("Loaded ML model state from disk")
	}

	return m
}

// Predict implements aidetection.MLModel with the built-in statistical
// fallback model.
func (m *SimpleThresholdModel) Predict(features aidetection.MLFeatures) aidetection.MLPredictionResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	signalScore := m.calculateSignalScore(features)
	temporalScore := m.calculateTemporalScore(features)
	networkScore := m.calculateNetworkScore(features)
	behavioralScore := m.calculateBehavioralScore(features)
	compositionScore := m.calculateCompositionScore(features)
	threatIntelScore := m.calculateThreatIntelScore(features)

	botProbability := (signalScore * m.signalCountWeight) +
		(temporalScore * m.temporalWeight) +
		(networkScore * m.networkWeight) +
		(behavioralScore * m.behavioralWeight) +
		(compositionScore * m.compositionWeight) +
		(threatIntelScore * m.threatIntelWeight)

	botProbability = math.Max(0, math.Min(1, botProbability))
	category := m.categorizeBot(features, botProbability)

	return aidetection.MLPredictionResult{
		IsBot:          botProbability >= m.botThreshold,
		Confidence:     botProbability,
		BotProbability: botProbability,
		Category:       category,
		ModelTier:      "statistical",
	}
}

// calculateSignalScore computes a normalized signal feature score (0.0-1.0) for ML PREDICTION.
//
// Purpose: This function transforms raw signal metrics into a normalized feature score
// for the ML model to predict "how bot-like is this entity?" (PREDICTIVE scoring).
//
// This is DIFFERENT from detection confidence (pkg/analyzer/aidetection/confidence.go):
//   - ML Feature Scoring (this function): "How bot-like?" - Uses z-scores & sigmoid for prediction
//   - Detection Confidence (confidence.go): "How reliable is this detection?" - Post-hoc assessment
//
// This function uses:
//   - Z-scores normalized against learned mean/stddev (adaptive to traffic patterns)
//   - Sigmoid transformation (maps z-scores to 0-1 probability-like scores)
//   - Weighted combination (count 40%, diversity 30%, rate 30%)
//
// Use this when: Training/predicting with the ML model, feature engineering
func (m *SimpleThresholdModel) calculateSignalScore(features aidetection.MLFeatures) float64 {
	zScore := (float64(features.SignalCount) - m.meanSignalCount) / m.stdSignalCount
	countScore := 1.0 / (1.0 + math.Exp(-zScore))
	diversityScore := math.Min(1.0, float64(features.SignalDiversity)/10.0)
	rateZScore := (features.SignalRate - m.meanSignalRate) / m.stdSignalRate
	rateScore := 1.0 / (1.0 + math.Exp(-rateZScore))
	return (countScore*0.4 + diversityScore*0.3 + rateScore*0.3)
}

func (m *SimpleThresholdModel) calculateTemporalScore(features aidetection.MLFeatures) float64 {
	score := 0.0
	if features.IsBursty {
		score += 0.5
	}
	if features.TimeOfDay < 6 || features.TimeOfDay > 22 {
		score += 0.3
	}
	if features.TimeSpan < 60 && features.SignalCount > 5 {
		score += 0.2
	}
	return math.Min(1.0, score)
}

func (m *SimpleThresholdModel) calculateNetworkScore(features aidetection.MLFeatures) float64 {
	score := 0.0
	if !features.HasJA4H {
		score += 0.4
	}
	if features.HasASN {
		score += 0.1
	}
	return math.Min(1.0, score)
}

func (m *SimpleThresholdModel) calculateBehavioralScore(features aidetection.MLFeatures) float64 {
	score := 0.0
	if features.RequestRate > 10.0 {
		score += 0.4
	} else if features.RequestRate > 5.0 {
		score += 0.2
	}
	if features.DetectionHistory > 0 {
		score += math.Min(0.5, float64(features.DetectionHistory)*0.1)
	}
	if features.ReputationScore < 0.3 {
		score += 0.3
	}
	return math.Min(1.0, score)
}

func (m *SimpleThresholdModel) calculateThreatIntelScore(features aidetection.MLFeatures) float64 {
	score := 0.0

	// Known scanner = very high score
	if features.IsKnownScanner {
		score += 0.80
	} else {
		// Threat score contribution (0-100 scale normalized to 0-0.5)
		if features.ThreatScore > 0 {
			score += (features.ThreatScore / 100.0) * 0.5
		}
	}

	// Vulnerabilities = compromised host indicator
	if features.HasVulnerabilities {
		score += 0.15
	}

	// Many open ports = likely scanner
	if features.OpenPortCount > 10 {
		score += 0.20
	} else if features.OpenPortCount > 5 {
		score += 0.10
	}

	// Tor/VPN = anonymization (moderate suspicion)
	if features.IsTor {
		score += 0.15
	} else if features.IsVPN {
		score += 0.08
	}

	// Cloud hosting = less suspicious (unless combined with other factors)
	if features.IsCloud && !features.IsKnownScanner && features.ThreatScore < 30 {
		score -= 0.10
	}

	return math.Max(0.0, math.Min(1.0, score))
}

func (m *SimpleThresholdModel) calculateCompositionScore(features aidetection.MLFeatures) float64 {
	score := 0.0
	totalSignals := features.SignalCount
	if totalSignals == 0 {
		return 0.0
	}

	highValueSignals := []aidetection.SignalType{
		aidetection.SignalPortScanning,
		aidetection.SignalIncompleteHandshake,
		aidetection.SignalJA4TAbuse,
		aidetection.SignalTimingPattern,
		aidetection.SignalGeoAnomaly,
	}

	for _, sigType := range highValueSignals {
		if count, exists := features.SignalTypeVector[sigType]; exists && count > 0 {
			score += 0.15
		}
	}

	sourceCount := len(features.SourceVector)
	if sourceCount >= 3 {
		score += 0.2
	} else if sourceCount >= 2 {
		score += 0.1
	}

	return math.Min(1.0, score)
}

func (m *SimpleThresholdModel) categorizeBot(features aidetection.MLFeatures, probability float64) aidetection.BotCategory {
	if probability < m.botThreshold {
		return aidetection.BotCategoryUnknown
	}

	// Threat intel provides strong categorization hints
	if features.IsKnownScanner {
		return aidetection.BotCategoryScanner
	}

	// Port scanning signals
	if features.SignalTypeVector[aidetection.SignalPortScanning] > 5 {
		return aidetection.BotCategoryScanner
	}

	// DDoS patterns (per window, conservative)
	if features.SignalTypeVector[aidetection.SignalIncompleteHandshake] > 400 &&
		(features.SignalTypeVector[aidetection.SignalHighFrequency] > 0 ||
			features.SignalTypeVector[aidetection.SignalConnectionPattern] > 0 ||
			features.SignalTypeVector[aidetection.SignalUDPFlood] > 0 ||
			features.SignalTypeVector[aidetection.SignalICMPFlood] > 0 ||
			features.SignalTypeVector[aidetection.SignalSYNFlood] > 0) {
		return aidetection.BotCategoryDDoS
	}

	// High threat score + many open ports = scanner
	if features.ThreatScore > 60 && features.OpenPortCount > 10 {
		return aidetection.BotCategoryScanner
	}

	// Script/tool indicators
	if features.SignalTypeVector[aidetection.SignalBotUA] > 0 ||
		features.SignalTypeVector[aidetection.SignalNoCookies] > 0 {
		return aidetection.BotCategoryScript
	}

	// Scraper patterns
	if features.RequestRate > 5.0 && features.SignalDiversity > 3 {
		return aidetection.BotCategoryScraper
	}

	// Timing patterns = scripted bot
	if features.SignalTypeVector[aidetection.SignalTimingPattern] > 0 {
		return aidetection.BotCategoryScript
	}

	return aidetection.BotCategoryUnknown
}

func (m *SimpleThresholdModel) Train(features aidetection.MLFeatures, isBot bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alpha := 0.1
	m.observationCount++

	delta := float64(features.SignalCount) - m.meanSignalCount
	m.meanSignalCount += alpha * delta
	m.stdSignalCount = math.Sqrt((1-alpha)*m.stdSignalCount*m.stdSignalCount + alpha*delta*delta)

	delta = features.SignalRate - m.meanSignalRate
	m.meanSignalRate += alpha * delta
	m.stdSignalRate = math.Sqrt((1-alpha)*m.stdSignalRate*m.stdSignalRate + alpha*delta*delta)

	m.lastUpdate = time.Now()

	// Save state every 10 observations to avoid excessive disk I/O
	if m.observationCount%10 == 0 {
		go func() {
			if err := m.Save(); err != nil {
				logrus.WithError(err).Error("Failed to save ML model state")
			}
		}()
	}

	return nil
}

func (m *SimpleThresholdModel) GetModelType() ModelType {
	return ModelLogisticRegression
}

func (m *SimpleThresholdModel) GetVersion() string {
	return "1.0.0-threshold-baseline"
}

// modelState represents the serializable state of the model
type modelState struct {
	MeanSignalCount  float64   `json:"mean_signal_count"`
	StdSignalCount   float64   `json:"std_signal_count"`
	MeanSignalRate   float64   `json:"mean_signal_rate"`
	StdSignalRate    float64   `json:"std_signal_rate"`
	ObservationCount uint64    `json:"observation_count"`
	LastUpdate       time.Time `json:"last_update"`
}

// Save persists the model's learned parameters to disk
func (m *SimpleThresholdModel) Save() error {
	if m.persistencePath == "" {
		return nil
	}

	m.mu.RLock()
	state := modelState{
		MeanSignalCount:  m.meanSignalCount,
		StdSignalCount:   m.stdSignalCount,
		MeanSignalRate:   m.meanSignalRate,
		StdSignalRate:    m.stdSignalRate,
		ObservationCount: m.observationCount,
		LastUpdate:       m.lastUpdate,
	}
	m.mu.RUnlock()

	// Create directory if it doesn't exist
	dir := filepath.Dir(m.persistencePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(m.persistencePath, data, 0644)
}

// Load restores the model's learned parameters from disk
func (m *SimpleThresholdModel) Load() error {
	if m.persistencePath == "" {
		return nil
	}

	data, err := os.ReadFile(m.persistencePath)
	if err != nil {
		return err
	}

	var state modelState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	m.mu.Lock()
	m.meanSignalCount = state.MeanSignalCount
	m.stdSignalCount = state.StdSignalCount
	m.meanSignalRate = state.MeanSignalRate
	m.stdSignalRate = state.StdSignalRate
	m.observationCount = state.ObservationCount
	m.lastUpdate = state.LastUpdate
	m.mu.Unlock()

	return nil
}

// ModelManager manages ML models for bot detection
type ModelManager struct {
	mu            sync.RWMutex
	primaryModel  aidetection.MLModel
	fallbackModel aidetection.MLModel
	enabled       bool
	minSamples    int
	sampleCount   int
}

func NewModelManager() *ModelManager {
	return &ModelManager{
		primaryModel:  NewSimpleThresholdModel(),
		fallbackModel: NewSimpleThresholdModel(),
		enabled:       true,
		minSamples:    10,
		sampleCount:   0,
	}
}

func (mm *ModelManager) Predict(features aidetection.MLFeatures) aidetection.MLPredictionResult {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	if !mm.enabled {
		return aidetection.MLPredictionResult{
			IsBot:      false,
			Confidence: 0.0,
		}
	}

	if mm.sampleCount < mm.minSamples {
		return mm.fallbackModel.Predict(features)
	}

	return mm.primaryModel.Predict(features)
}

func (mm *ModelManager) Train(features aidetection.MLFeatures, isBot bool) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	mm.sampleCount++

	if err := mm.primaryModel.Train(features, isBot); err != nil {
		return err
	}

	return mm.fallbackModel.Train(features, isBot)
}

// GetPrimaryModel returns the primary model (if it's an ONNX model)
func (mm *ModelManager) GetPrimaryModel() aidetection.MLModel {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	return mm.primaryModel
}

// SetPrimaryModel sets a new primary model
func (mm *ModelManager) SetPrimaryModel(model aidetection.MLModel) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.primaryModel = model
}

func (mm *ModelManager) SetEnabled(enabled bool) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.enabled = enabled
}

func (mm *ModelManager) GetStats() map[string]interface{} {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	return map[string]interface{}{
		"enabled":      mm.enabled,
		"sample_count": mm.sampleCount,
		"min_samples":  mm.minSamples,
		"model_type":   "simple_threshold",
	}
}
