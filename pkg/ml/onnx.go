package ml

import (
	"fmt"
	"math"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
	onnxruntime "github.com/yalue/onnxruntime_go"

	"PacketYeeter/pkg/analyzer/aidetection"
)

// ONNXModel wraps an ONNX model for inference using onnxruntime
type ONNXModel struct {
	mu          sync.RWMutex
	modelPath   string
	session     *onnxruntime.DynamicAdvancedSession
	nFeatures   int
	threshold   float64
	outputNames []string // Track which outputs the model actually has
}

// LoadONNXModel loads an ONNX model from disk
func LoadONNXModel(modelPath string, threshold float64) (*ONNXModel, error) {
	model, err := loadONNXModelInternal(modelPath, threshold)
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"model_path":   modelPath,
		"n_features":   model.nFeatures,
		"threshold":    threshold,
		"output_names": model.outputNames,
	}).Info("✓ ONNX model loaded successfully")

	return model, nil
}

// Predict runs inference on the model
func (m *ONNXModel) Predict(features aidetection.MLFeatures) aidetection.MLPredictionResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Convert features to float32 tensor
	inputData := m.featuresToTensor(features)

	// Create input tensor
	inputShape := onnxruntime.NewShape(1, int64(m.nFeatures))
	inputTensor, err := onnxruntime.NewTensor(inputShape, inputData)
	if err != nil {
		logrus.WithError(err).Error("Failed to create input tensor")
		return m.fallbackPredict(features)
	}
	defer inputTensor.Destroy()

	// Prepare output tensors based on what the model provides
	var labelTensor *onnxruntime.Tensor[int64]
	var probTensor *onnxruntime.Tensor[float32]
	var outputs []onnxruntime.Value

	if len(m.outputNames) >= 2 {
		// Model has both label and probabilities
		labelShape := onnxruntime.NewShape(1)
		labelTensor, err = onnxruntime.NewEmptyTensor[int64](labelShape)
		if err != nil {
			logrus.WithError(err).Error("Failed to create label tensor")
			return m.fallbackPredict(features)
		}
		defer labelTensor.Destroy()

		// Probabilities shape: [1, 2] for binary classification
		probShape := onnxruntime.NewShape(1, 2)
		probTensor, err = onnxruntime.NewEmptyTensor[float32](probShape)
		if err != nil {
			logrus.WithError(err).Error("Failed to create probability tensor")
			return m.fallbackPredict(features)
		}
		defer probTensor.Destroy()

		outputs = []onnxruntime.Value{labelTensor, probTensor}
	} else {
		// Model only has label output
		labelShape := onnxruntime.NewShape(1)
		labelTensor, err = onnxruntime.NewEmptyTensor[int64](labelShape)
		if err != nil {
			logrus.WithError(err).Error("Failed to create label tensor")
			return m.fallbackPredict(features)
		}
		defer labelTensor.Destroy()
		outputs = []onnxruntime.Value{labelTensor}
	}

	// Run inference - outputs are populated in-place
	err = m.session.Run([]onnxruntime.Value{inputTensor}, outputs)
	if err != nil {
		logrus.WithError(err).Error("ONNX inference failed")
		return m.fallbackPredict(features)
	}

	// Extract predicted class
	labelData := labelTensor.GetData()
	predictedClass := labelData[0]
	isBot := predictedClass == 1

	// Extract probability if available
	var botProbability float64
	if probTensor != nil {
		// probabilities tensor: [prob_class_0, prob_class_1]
		probData := probTensor.GetData()
		if len(probData) >= 2 {
			botProbability = float64(probData[1]) // Probability of class 1 (bot)
		} else {
			// Fallback if probability format is unexpected
			botProbability = 0.85
			if !isBot {
				botProbability = 0.15
			}
		}
	} else {
		// No probabilities available, use threshold-based confidence
		botProbability = 0.85
		if !isBot {
			botProbability = 0.15
		}
	}

	confidence := botProbability
	if !isBot {
		confidence = 1.0 - botProbability
	}

	// CRITICAL: Calibrate confidence based on signal quality
	// ML model is overconfident with limited signals
	confidence = m.calibrateConfidence(confidence, features)

	// Infer category from signals
	category := m.inferCategory(features)

	return aidetection.MLPredictionResult{
		IsBot:          isBot,
		BotProbability: botProbability,
		Confidence:     confidence,
		Category:       category,
	}
}

// inferCategory determines bot category from signal patterns
func (m *ONNXModel) inferCategory(features aidetection.MLFeatures) aidetection.BotCategory {
	// Check for scanner patterns
	if features.SignalTypeVector[aidetection.SignalPortScanning] > 3 {
		return aidetection.BotCategoryScanner
	}

	// Check for DDoS patterns
	ddosSignals := features.SignalTypeVector[aidetection.SignalICMPFlood] +
		features.SignalTypeVector[aidetection.SignalUDPFlood] +
		features.SignalTypeVector[aidetection.SignalSYNFlood]
	if ddosSignals > 10 {
		return aidetection.BotCategoryDDoS
	}

	// Check for scraper patterns
	if features.SignalTypeVector[aidetection.SignalPathSeqIDs] > 5 ||
		features.SignalTypeVector[aidetection.SignalPathEntropyLow] > 5 {
		return aidetection.BotCategoryScraper
	}

	return aidetection.BotCategoryMalicious
}

// calibrateConfidence adjusts ML confidence based on signal quality and quantity
// Prevents overconfident predictions with weak evidence
func (m *ONNXModel) calibrateConfidence(rawConfidence float64, features aidetection.MLFeatures) float64 {
	signalCount := features.SignalCount
	signalDiversity := features.SignalDiversity

	// Very low signal count = cap confidence aggressively
	// 1-3 signals: max 70% confidence
	// 4-5 signals: max 80% confidence
	// 6-8 signals: max 90% confidence
	// 9+ signals: no cap (allow model confidence)

	var maxConfidence float64
	switch {
	case signalCount <= 3:
		maxConfidence = 0.70 // TCP metadata alone shouldn't be >70%
	case signalCount <= 5:
		maxConfidence = 0.80
	case signalCount <= 8:
		maxConfidence = 0.90
	default:
		maxConfidence = 1.0 // No cap for strong evidence
	}

	// Further reduce if low diversity (same signal type repeated)
	// Diversity 1 = same signal type, should be less confident
	if signalDiversity == 1 && signalCount > 1 {
		maxConfidence *= 0.85 // 15% reduction for no diversity
	} else if signalDiversity == 2 && signalCount > 3 {
		maxConfidence *= 0.92 // 8% reduction for minimal diversity
	}

	// Apply the cap
	calibrated := math.Min(rawConfidence, maxConfidence)

	// If confidence was capped significantly, log it
	if rawConfidence > maxConfidence+0.1 {
		logrus.WithFields(logrus.Fields{
			"raw_confidence": rawConfidence,
			"calibrated":     calibrated,
			"signal_count":   signalCount,
			"diversity":      signalDiversity,
		}).Debug("ML confidence calibrated due to weak evidence")
	}

	return calibrated
}

// fallbackPredict uses simple threshold model if ONNX fails
func (m *ONNXModel) fallbackPredict(features aidetection.MLFeatures) aidetection.MLPredictionResult {
	logrus.Debug("Using fallback threshold model for prediction")
	fallbackModel := NewSimpleThresholdModel()
	return fallbackModel.Predict(features)
}

// Train is not supported for ONNX models (they are pre-trained)
func (m *ONNXModel) Train(features aidetection.MLFeatures, isBot bool) error {
	// ONNX models are static and cannot be trained online
	return nil
}

// Close releases model resources
func (m *ONNXModel) Close() error {
	if m.session != nil {
		if err := m.session.Destroy(); err != nil {
			return fmt.Errorf("failed to destroy ONNX session: %w", err)
		}
	}
	return nil
}

// featuresToTensor converts MLFeatures to flat float32 slice
// Order MUST match training feature order in train_model.py!
func (m *ONNXModel) featuresToTensor(features aidetection.MLFeatures) []float32 {
	// Check if we should use advanced features (100+ feature model)
	if m.nFeatures >= 100 && features.EventHistory != nil {
		return m.featuresToTensorAdvanced(features)
	}

	// Fall back to legacy 41-feature extraction
	return m.featuresToTensorLegacy(features)
}

// copyTruncated copies as much of src into dst starting at offset as fits,
// silently dropping any tail that would exceed dst's length. Used so smaller
// auto-detected model sizes (100/106/110 features) don't panic when a
// feature block sized for the full 126-feature layout doesn't fit.
func copyTruncated(dst []float32, offset int, src []float32) {
	if offset >= len(dst) {
		return
	}
	end := offset + len(src)
	if end > len(dst) {
		end = len(dst)
	}
	copy(dst[offset:end], src)
}

// featuresToTensorAdvanced extracts 126 features from event history
func (m *ONNXModel) featuresToTensorAdvanced(features aidetection.MLFeatures) []float32 {
	// Allocate based on model's actual feature count
	tensor := make([]float32, m.nFeatures)

	if features.EventHistory == nil {
		logrus.Warn("Advanced feature extraction requested but no event history available")
		return tensor // Return zeros
	}

	extractor := &AdvancedFeatureExtractor{}

	// Temporal features (25)
	temporalFeats := extractor.ExtractTemporalFeatures(*features.EventHistory)
	copy(tensor[0:25], temporalFeats)

	// Path features (20)
	pathFeats := extractor.ExtractPathFeatures(*features.EventHistory)
	copy(tensor[25:45], pathFeats)

	// Header features (25)
	headerFeats := extractor.ExtractHeaderFeatures(*features.EventHistory)
	copy(tensor[45:70], headerFeats)

	// Signal features (25) - includes status code features
	signalFeats := extractor.ExtractSignalFeatures(*features.EventHistory)
	copy(tensor[70:95], signalFeats)

	// Fingerprint features (10) and behavioral features (10) normally occupy
	// tensor[95:115]. Auto-detected model sizes 100/106/110 (see the probe
	// list in loadONNXModelInternal) are narrower than that, so copyTruncated
	// clamps each write to the tensor's actual capacity instead of writing
	// the fixed offsets unconditionally, which would panic with a
	// slice-bounds-out-of-range on those sizes.
	fingerprintFeats := extractor.ExtractFingerprintFeatures(*features.EventHistory, features.JA4, features.JA4H, features.JA4T)
	copyTruncated(tensor, 95, fingerprintFeats)

	// Behavioral features (10) - requires splitting events into pre/post
	// For now, use all events as both pre and post (simplified)
	behavioralFeats := extractor.ExtractBehavioralFeatures(
		features.EventHistory.Events,
		features.EventHistory.Events,
		features.EventHistory.Timestamps,
		features.EventHistory.Timestamps,
	)
	copyTruncated(tensor, 105, behavioralFeats)

	// Original detection features (11) - only if model supports 126 features
	if m.nFeatures >= 126 {
		tensor[115] = float32(features.Confidence)
		tensor[116] = float32(features.SignalCount)
		if features.WouldBlock {
			tensor[117] = 1.0
		}
		tensor[118] = float32(features.ThreatScore)
		if features.JA4 != "" {
			tensor[119] = 1.0
		}
		if features.JA4H != "" {
			tensor[120] = 1.0
		}
		if features.JA4T != "" {
			tensor[121] = 1.0
		}
		tensor[122] = float32(features.PathCount)
		tensor[123] = float32(features.UserAgentCount)
		tensor[124] = float32(features.ASN)
		tensor[125] = float32(features.AsnReputation)
	} else if m.nFeatures == 116 {
		// Old 116-feature model layout (no fingerprints, simplified detection features)
		// Overwrite fingerprint section with detection features
		tensor[95] = float32(features.Confidence)
		tensor[96] = float32(features.SignalCount)
		if features.WouldBlock {
			tensor[97] = 1.0
		}
		tensor[98] = float32(features.ThreatScore)
		if features.JA4 != "" {
			tensor[99] = 1.0
		}
		// Behavioral still at 105-115, but limit to what fits
		if m.nFeatures > 115 {
			// 116-feature model has room for 1 more feature
			tensor[115] = behavioralFeats[9] // Last behavioral feature
		}
	}

	return tensor
}

// featuresToTensorLegacy is the original 41-feature extraction
func (m *ONNXModel) featuresToTensorLegacy(features aidetection.MLFeatures) []float32 {
	tensor := make([]float32, 0, m.nFeatures)

	// Core features (3) - MUST match train_model.py extract_features() exactly!
	// Python training: signal_count, signal_rate, signal_rate (duplicate for backward compat)
	tensor = append(tensor, float32(features.SignalCount))
	tensor = append(tensor, float32(features.SignalRate))
	tensor = append(tensor, float32(features.SignalRate)) // Intentional duplicate to match training

	// Signal type features (16) - MUST match train_model.py extract_features() order exactly!
	// Python order: ['high_frequency', 'path_seq_ids', 'missing_accept_language',
	//                'clock_skew_anomaly', 'entropy_low', 'high_threat_score', 'ua_suspicious',
	//                'missing_ja4h', 'incomplete_handshake', 'bad_flags', 'connection_pattern',
	//                'timing_pattern', 'proxy_lag', 'icmp_flood', 'udp_flood', 'syn_flood']
	signalTypes := []aidetection.SignalType{
		aidetection.SignalHighFrequency, aidetection.SignalPathSeqIDs, aidetection.SignalMissingAcceptLang,
		aidetection.SignalClockSkewAnomaly, aidetection.SignalEntropyLow, aidetection.SignalHighThreatScore, aidetection.SignalSuspiciousUA,
		aidetection.SignalMissingJA4H, aidetection.SignalIncompleteHandshake, aidetection.SignalBadFlags, aidetection.SignalConnectionPattern,
		aidetection.SignalTimingPattern, aidetection.SignalProxyLag, aidetection.SignalICMPFlood, aidetection.SignalUDPFlood, aidetection.SignalSYNFlood,
	}
	for _, sigType := range signalTypes {
		tensor = append(tensor, float32(features.SignalTypeVector[sigType]))
	}

	// Source breakdown features (5) - MUST match train_model.py extract_features() order exactly!
	// Python order: ['spoe', 'tcp', 'udp', 'icmp', 'fingerprint']
	sources := []aidetection.SignalSource{
		aidetection.SourceSPOE, aidetection.SourceTCP, aidetection.SourceUDP,
		aidetection.SourceICMP, aidetection.SourceFingerprint,
	}
	for _, source := range sources {
		tensor = append(tensor, float32(features.SourceVector[source]))
	}

	// Derived features (5)
	totalSignals := 0
	for _, count := range features.SignalTypeVector {
		totalSignals += count
	}
	if totalSignals == 0 {
		totalSignals = 1
	}

	// sig_diversity
	uniqueSignals := 0
	for _, count := range features.SignalTypeVector {
		if count > 0 {
			uniqueSignals++
		}
	}
	tensor = append(tensor, float32(uniqueSignals)/float32(len(signalTypes)))

	// high_freq_ratio
	tensor = append(tensor, float32(features.SignalTypeVector[aidetection.SignalHighFrequency])/float32(totalSignals))

	// enum_ratio
	tensor = append(tensor, float32(features.SignalTypeVector[aidetection.SignalPathSeqIDs])/float32(totalSignals))

	// ddos_signals
	ddosSignals := features.SignalTypeVector[aidetection.SignalICMPFlood] +
		features.SignalTypeVector[aidetection.SignalUDPFlood] +
		features.SignalTypeVector[aidetection.SignalSYNFlood]
	tensor = append(tensor, float32(ddosSignals))

	// scraper_signals
	scraperSignals := features.SignalTypeVector[aidetection.SignalPathSeqIDs] +
		features.SignalTypeVector[aidetection.SignalMissingAcceptLang]
	tensor = append(tensor, float32(scraperSignals))

	// Threat Intelligence features (6)
	tensor = append(tensor, float32(features.ThreatScore))
	if features.IsKnownScanner {
		tensor = append(tensor, 1.0)
	} else {
		tensor = append(tensor, 0.0)
	}
	if features.IsCloud {
		tensor = append(tensor, 1.0)
	} else {
		tensor = append(tensor, 0.0)
	}
	if features.IsTor {
		tensor = append(tensor, 1.0)
	} else {
		tensor = append(tensor, 0.0)
	}
	if features.IsVPN {
		tensor = append(tensor, 1.0)
	} else {
		tensor = append(tensor, 0.0)
	}
	tensor = append(tensor, float32(features.OpenPortCount))

	// Behavioral features (3)
	tensor = append(tensor, float32(features.ReputationScore))
	tensor = append(tensor, float32(features.DetectionHistory))
	tensor = append(tensor, float32(features.RequestRate))

	// Temporal features (3)
	tensor = append(tensor, float32(features.TimeOfDay))
	tensor = append(tensor, float32(features.DayOfWeek))
	if features.IsBursty {
		tensor = append(tensor, 1.0)
	} else {
		tensor = append(tensor, 0.0)
	}

	// Total features: 3 (core) + 16 (signals) + 5 (sources) + 5 (derived) + 6 (threat_intel) + 3 (behavioral) + 3 (temporal) = 41 features
	// This matches train_model.py extract_features() exactly

	// Validation: ensure we generated exactly the expected number of features
	if len(tensor) != m.nFeatures {
		sampleSize := 10
		if len(tensor) < sampleSize {
			sampleSize = len(tensor)
		}
		logrus.WithFields(logrus.Fields{
			"expected":      m.nFeatures,
			"got":           len(tensor),
			"signal_count":  features.SignalCount,
			"signal_rate":   features.SignalRate,
			"threat_score":  features.ThreatScore,
			"tensor_sample": tensor[:sampleSize],
		}).Error("CRITICAL: Feature count mismatch! Model will produce incorrect predictions!")
		// Pad or truncate to avoid crashes, but this indicates a bug
		if len(tensor) < m.nFeatures {
			// Pad with zeros
			for i := len(tensor); i < m.nFeatures; i++ {
				tensor = append(tensor, 0.0)
			}
		} else {
			// Truncate
			tensor = tensor[:m.nFeatures]
		}
	}

	return tensor
}

// Reload reloads the model from disk (used by ModelWatcher)
func (m *ONNXModel) Reload(modelPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Load new model with same threshold
	newModel, err := loadONNXModelInternal(modelPath, m.threshold)
	if err != nil {
		return fmt.Errorf("failed to load new model: %w", err)
	}

	// Close old session
	if m.session != nil {
		m.session.Destroy()
	}

	// Replace with new session
	m.session = newModel.session
	m.outputNames = newModel.outputNames
	m.nFeatures = newModel.nFeatures
	m.modelPath = modelPath

	return nil
}

// loadONNXModelInternal is the internal version without mutex (called during Reload)
func loadONNXModelInternal(modelPath string, threshold float64) (*ONNXModel, error) {
	// Check if file exists
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("model file not found: %s", modelPath)
	}

	// Initialize ONNX Runtime library (safe to call multiple times)
	if err := onnxruntime.InitializeEnvironment(); err != nil {
		// Ignore if already initialized
		logrus.WithError(err).Debug("ONNX Runtime environment already initialized")
	}

	logrus.WithField("model_path", modelPath).Info("Loading ONNX model with onnxruntime")

	// XGBoost ONNX models can have different output names depending on version
	var session *onnxruntime.DynamicAdvancedSession
	var outputNames []string
	var err error

	// Try newer format first (label, probabilities)
	session, err = onnxruntime.NewDynamicAdvancedSession(modelPath, []string{"float_input"}, []string{"label", "probabilities"}, nil)
	if err == nil {
		outputNames = []string{"label", "probabilities"}
		logrus.Info("Using ONNX outputs: label, probabilities")
	} else {
		// Try older format (output_label, output_probability)
		session, err = onnxruntime.NewDynamicAdvancedSession(modelPath, []string{"float_input"}, []string{"output_label", "output_probability"}, nil)
		if err == nil {
			outputNames = []string{"output_label", "output_probability"}
			logrus.Info("Using ONNX outputs: output_label, output_probability")
		} else {
			// Try just label
			session, err = onnxruntime.NewDynamicAdvancedSession(modelPath, []string{"float_input"}, []string{"label"}, nil)
			if err == nil {
				outputNames = []string{"label"}
				logrus.Info("Using ONNX output: label")
			} else {
				return nil, fmt.Errorf("failed to load ONNX model with any known output format: %w", err)
			}
		}
	}

	if session == nil {
		return nil, fmt.Errorf("failed to create ONNX session")
	}

	// Try to auto-detect feature count by testing inference with different sizes
	nFeatures := 41 // Default fallback

	logrus.Info("Auto-detecting model feature count...")
	for _, testSize := range []int{126, 116, 110, 106, 100, 144, 41, 50} {
		logrus.WithField("testing_size", testSize).Debug("Testing feature count")
		testShape := onnxruntime.NewShape(1, int64(testSize))
		testTensor, err := onnxruntime.NewEmptyTensor[float32](testShape)
		if err != nil {
			logrus.WithFields(logrus.Fields{"size": testSize, "error": err}).Debug("Failed to create test tensor")
			continue
		}

		// Create output tensors based on outputNames
		var outputs []onnxruntime.Value
		labelShape := onnxruntime.NewShape(1)
		labelTensor, err := onnxruntime.NewEmptyTensor[int64](labelShape)
		if err != nil {
			testTensor.Destroy()
			logrus.WithFields(logrus.Fields{"size": testSize, "error": err}).Debug("Failed to create label tensor")
			continue
		}
		outputs = append(outputs, labelTensor)

		// Add probability tensor if model has probabilities output
		var probTensor *onnxruntime.Tensor[float32]
		if len(outputNames) > 1 {
			probShape := onnxruntime.NewShape(1, 2) // Binary classification: [batch, 2]
			probTensor, err = onnxruntime.NewEmptyTensor[float32](probShape)
			if err != nil {
				testTensor.Destroy()
				labelTensor.Destroy()
				continue
			}
			outputs = append(outputs, probTensor)
		}

		err = session.Run([]onnxruntime.Value{testTensor}, outputs)
		testTensor.Destroy()
		labelTensor.Destroy()
		if probTensor != nil {
			probTensor.Destroy()
		}

		if err == nil {
			nFeatures = testSize
			logrus.WithField("detected_features", nFeatures).Info("✓ Auto-detected feature count from model")
			break
		} else {
			logrus.WithFields(logrus.Fields{"size": testSize, "error": err}).Debug("Inference test failed")
		}
	}

	if nFeatures == 41 {
		logrus.Warn("Auto-detection failed, using default 41 features")
	}

	return &ONNXModel{
		modelPath:   modelPath,
		session:     session,
		nFeatures:   nFeatures,
		threshold:   threshold,
		outputNames: outputNames,
	}, nil
}
