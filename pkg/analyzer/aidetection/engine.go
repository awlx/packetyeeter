package aidetection

import (
	"container/ring"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/analyzer/threatintel"
	"PacketYeeter/pkg/geoip"
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/utils/ewma"
)

// Engine is the central AI detection engine that receives signals from multiple sources
type Engine struct {
	mu                sync.RWMutex
	signalChan        chan Signal
	stop              chan struct{}
	workers           int
	detectionHandlers []DetectionHandler

	// EWMA tracking for adaptive detection
	ewmaMap map[string]*ewma.State
	ewmaMu  sync.Mutex

	// Configuration
	ewmaTau             time.Duration
	staticThreshold     int
	ewmaMultiplier      float64
	ewmaMinBaseline     float64
	startupTime         time.Time
	warmupPeriod        time.Duration
	confidenceThreshold float64

	ddosIncompleteThreshold  int
	ddosPatternThreshold     int
	ddosTotalThreshold       int
	ddosRequireHighFreq      bool
	enableDDoSCategory       bool
	ddosMinFloodWeight       float64
	ddosMinIPFloodPPS        float64
	ddosMinASNFloodPPS       float64
	suspiciousScoreThreshold float64
	blockScoreThreshold      float64
	campaigns                *CampaignAggregator

	// Dependencies
	geoip           *geoip.Provider
	reputation      *reputation.Engine
	ja4Verifier     JA4Verifier
	crawlerVerifier *CrawlerVerifier
	mlModel         MLModel // Machine learning model for bot detection
	threatIntel     *threatintel.ThreatIntelligence
	feedback        *FeedbackLoop // Adaptive threshold adjustment based on outcomes

	// Metrics tracking
	signalsByIP      map[string]uint64
	detectionsByIP   map[string]uint64
	signalsByASN     map[string]uint64
	detectionsByASN  map[string]uint64
	signalsByJA4H    map[string]uint64
	detectionsByJA4H map[string]uint64

	// Detailed signal tracking by entity
	signalTypesByIP   map[string]map[string]uint64 // IP -> signal type -> count
	signalTypesByASN  map[string]map[string]uint64 // ASN -> signal type -> count
	signalTypesByJA4H map[string]map[string]uint64 // JA4H -> signal type -> count

	signalSourcesByIP   map[string]map[string]uint64 // IP -> source -> count
	signalSourcesByASN  map[string]map[string]uint64 // ASN -> source -> count
	signalSourcesByJA4H map[string]map[string]uint64 // JA4H -> source -> count

	// Behavioral profiling
	behavioralProfiles map[string]*BehavioralProfile // Entity ID -> profile
	profilesMu         sync.Mutex

	// ML Tier tracking (last 1000 predictions)
	mlTierCounts    map[string]int // pattern/onnx/statistical -> count
	mlTierHistory   []string       // Rolling buffer of last 1000 tiers
	mlTierHistoryMu sync.Mutex

	// Session recording for ML training
	sessionRecordings    map[string]*SessionRecording // IP -> active recording
	sessionRecordingsMu  sync.Mutex
	preDetectionBuffers  map[string]*ring.Ring // IP -> last 100 signals
	preDetectionBufferMu sync.Mutex

	// Event history for advanced feature extraction (Option 2)
	historyManager *HistoryManager

	// Rate limiting for buffer warnings
	lastBufferWarning      time.Time
	bufferWarningMu        sync.Mutex
	completedRecordings    []*SessionRecording // Finalized recordings ready for export
	completedRecordingsMu  sync.Mutex
	maxCompletedRecordings int // Max recordings to keep before export

	// Latest detections cache for UI display
	latestDetections map[string]*DetectionEvent // Entity ID -> latest detection
	detectionsMu     sync.Mutex

	// Detection history for last 6 hours
	detectionHistory []*DetectionEvent
	historyMu        sync.Mutex
	historyMaxAge    time.Duration // How long to keep history (default: 6 hours)
	historyMaxSize   int           // Max number of detections to keep (default: 10000)

	metricsMu sync.Mutex

	// ASN activity tracking
	asnActiveIPs  map[string]map[string]time.Time // ASN -> IP -> last seen
	asnAbusiveIPs map[string]map[string]time.Time // ASN -> IP -> last detected
	asnOrg        map[string]string               // ASN -> org label
	asnMapsMu     sync.Mutex
	asnTTL        time.Duration

	statePath string

	// Session recordings persistence
	sessionRecordingsPath string // Directory to store session recordings on disk

	// Log throttling
	logThrottle   map[string]time.Time
	logThrottleMu sync.Mutex
}

// Config holds the configuration for the AI detection engine
type Config struct {
	Workers               int
	BufferSize            int
	EWMATau               time.Duration
	StaticThreshold       int
	EWMAMultiplier        float64
	EWMAMinBaseline       float64
	WarmupPeriod          time.Duration // Don't block during warmup
	ConfidenceThreshold   float64       // AI detection confidence threshold (0-1)
	StatePath             string        // Optional persistence path for ASN/IP state
	SessionRecordingsPath string        // Directory to store session recordings (default: /var/cache/packetyeeter/sessions)
	GeoIP                 *geoip.Provider
	Reputation            *reputation.Engine
	JA4Verifier           JA4Verifier
	MLModel               MLModel // Machine learning model
	ThreatIntel           *threatintel.ThreatIntelligence

	// DDoS classification thresholds (per IP/JA4H per 10s window)
	DDoSIncompleteThreshold  int
	DDoSPatternThreshold     int
	DDoSTotalThreshold       int
	DDoSRequireHighFreq      bool
	EnableDDoSCategory       bool
	DDoSMinFloodWeight       float64
	DDoSMinIPFloodPPS        float64
	DDoSMinASNFloodPPS       float64
	SuspiciousScoreThreshold float64
	BlockScoreThreshold      float64

	// Campaign/carpet-bombing aggregation thresholds.
	Campaign CampaignConfig

	// Feedback loop configuration
	EnableFeedback bool
	FeedbackConfig FeedbackConfig
}

// DefaultConfig returns sensible defaults for the engine
func DefaultConfig() Config {
	return Config{
		Workers:                  16,
		BufferSize:               10000,
		EWMATau:                  60 * time.Second,
		StaticThreshold:          3,
		EWMAMultiplier:           3.0,
		EWMAMinBaseline:          1.0,
		WarmupPeriod:             5 * time.Minute, // warmup before blocking
		ConfidenceThreshold:      0.5,
		DDoSIncompleteThreshold:  400,
		DDoSPatternThreshold:     800,
		DDoSTotalThreshold:       1500,
		DDoSRequireHighFreq:      true,
		EnableDDoSCategory:       true,
		DDoSMinFloodWeight:       50,
		DDoSMinIPFloodPPS:        2000,
		DDoSMinASNFloodPPS:       200000,
		SuspiciousScoreThreshold: 5,
		BlockScoreThreshold:      15,
		Campaign:                 DefaultCampaignConfig(),
	}
}

// New creates a new AI detection engine
func New(cfg Config) *Engine {
	if cfg.Workers == 0 {
		cfg.Workers = DefaultConfig().Workers
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = DefaultConfig().BufferSize
	}
	if cfg.EWMATau == 0 {
		cfg.EWMATau = DefaultConfig().EWMATau
	}
	if cfg.StaticThreshold == 0 {
		cfg.StaticThreshold = DefaultConfig().StaticThreshold
	}
	if cfg.EWMAMultiplier == 0 {
		cfg.EWMAMultiplier = DefaultConfig().EWMAMultiplier
	}
	if cfg.ConfidenceThreshold == 0 {
		cfg.ConfidenceThreshold = DefaultConfig().ConfidenceThreshold
	}
	if cfg.EWMAMinBaseline == 0 {
		cfg.EWMAMinBaseline = DefaultConfig().EWMAMinBaseline
	}
	if cfg.WarmupPeriod == 0 {
		cfg.WarmupPeriod = DefaultConfig().WarmupPeriod
	}
	if cfg.DDoSIncompleteThreshold == 0 {
		cfg.DDoSIncompleteThreshold = DefaultConfig().DDoSIncompleteThreshold
	}
	if cfg.DDoSPatternThreshold == 0 {
		cfg.DDoSPatternThreshold = DefaultConfig().DDoSPatternThreshold
	}
	if cfg.DDoSTotalThreshold == 0 {
		cfg.DDoSTotalThreshold = DefaultConfig().DDoSTotalThreshold
	}
	if cfg.DDoSMinFloodWeight == 0 {
		cfg.DDoSMinFloodWeight = DefaultConfig().DDoSMinFloodWeight
	}
	if cfg.DDoSMinIPFloodPPS == 0 {
		cfg.DDoSMinIPFloodPPS = DefaultConfig().DDoSMinIPFloodPPS
	}
	if cfg.DDoSMinASNFloodPPS == 0 {
		cfg.DDoSMinASNFloodPPS = DefaultConfig().DDoSMinASNFloodPPS
	}
	if cfg.SuspiciousScoreThreshold == 0 {
		cfg.SuspiciousScoreThreshold = DefaultConfig().SuspiciousScoreThreshold
	}
	if cfg.BlockScoreThreshold == 0 {
		cfg.BlockScoreThreshold = DefaultConfig().BlockScoreThreshold
	}
	cfg.Campaign = normalizeCampaignConfig(cfg.Campaign)
	if !cfg.DDoSRequireHighFreq {
		cfg.DDoSRequireHighFreq = DefaultConfig().DDoSRequireHighFreq
	}
	// EnableDDoSCategory can be false explicitly; otherwise default true
	if !cfg.EnableDDoSCategory {
		cfg.EnableDDoSCategory = DefaultConfig().EnableDDoSCategory
	}

	e := &Engine{
		signalChan:               make(chan Signal, cfg.BufferSize),
		stop:                     make(chan struct{}),
		workers:                  cfg.Workers,
		ewmaMap:                  make(map[string]*ewma.State),
		ewmaTau:                  cfg.EWMATau,
		staticThreshold:          cfg.StaticThreshold,
		ewmaMultiplier:           cfg.EWMAMultiplier,
		ewmaMinBaseline:          cfg.EWMAMinBaseline,
		startupTime:              time.Now(),
		warmupPeriod:             cfg.WarmupPeriod,
		confidenceThreshold:      cfg.ConfidenceThreshold,
		ddosIncompleteThreshold:  cfg.DDoSIncompleteThreshold,
		ddosPatternThreshold:     cfg.DDoSPatternThreshold,
		ddosTotalThreshold:       cfg.DDoSTotalThreshold,
		ddosRequireHighFreq:      cfg.DDoSRequireHighFreq,
		enableDDoSCategory:       cfg.EnableDDoSCategory,
		ddosMinFloodWeight:       cfg.DDoSMinFloodWeight,
		ddosMinIPFloodPPS:        cfg.DDoSMinIPFloodPPS,
		ddosMinASNFloodPPS:       cfg.DDoSMinASNFloodPPS,
		suspiciousScoreThreshold: cfg.SuspiciousScoreThreshold,
		blockScoreThreshold:      cfg.BlockScoreThreshold,
		campaigns:                NewCampaignAggregator(cfg.Campaign),
		geoip:                    cfg.GeoIP,
		reputation:               cfg.Reputation,
		ja4Verifier:              cfg.JA4Verifier,
		crawlerVerifier:          NewCrawlerVerifier(cfg.JA4Verifier),
		mlModel:                  cfg.MLModel,
		threatIntel:              cfg.ThreatIntel,
		signalsByIP:              make(map[string]uint64),
		detectionsByIP:           make(map[string]uint64),
		signalsByASN:             make(map[string]uint64),
		detectionsByASN:          make(map[string]uint64),
		signalsByJA4H:            make(map[string]uint64),
		detectionsByJA4H:         make(map[string]uint64),

		signalTypesByIP:   make(map[string]map[string]uint64),
		signalTypesByASN:  make(map[string]map[string]uint64),
		signalTypesByJA4H: make(map[string]map[string]uint64),

		signalSourcesByIP:   make(map[string]map[string]uint64),
		signalSourcesByASN:  make(map[string]map[string]uint64),
		signalSourcesByJA4H: make(map[string]map[string]uint64),

		behavioralProfiles:     make(map[string]*BehavioralProfile),
		latestDetections:       make(map[string]*DetectionEvent),
		detectionHistory:       make([]*DetectionEvent, 0, 10000),
		historyMaxAge:          6 * time.Hour,
		historyMaxSize:         10000,
		logThrottle:            make(map[string]time.Time),
		asnActiveIPs:           make(map[string]map[string]time.Time),
		asnAbusiveIPs:          make(map[string]map[string]time.Time),
		asnOrg:                 make(map[string]string),
		asnTTL:                 30 * time.Minute,
		statePath:              cfg.StatePath,
		sessionRecordingsPath:  cfg.SessionRecordingsPath,
		mlTierCounts:           make(map[string]int),
		mlTierHistory:          make([]string, 0, 1000),
		sessionRecordings:      make(map[string]*SessionRecording),
		preDetectionBuffers:    make(map[string]*ring.Ring),
		completedRecordings:    make([]*SessionRecording, 0, 1000),
		maxCompletedRecordings: 1000,
		historyManager:         NewHistoryManager(200, 10*time.Minute, 1*time.Minute), // 200 events, 10min window
	}

	// Initialize feedback loop for adaptive threshold adjustment
	if cfg.EnableFeedback {
		if cfg.FeedbackConfig.MaxOutcomes == 0 {
			cfg.FeedbackConfig = DefaultFeedbackConfig()
		}
		cfg.FeedbackConfig.InitialThreshold = cfg.ConfidenceThreshold
		e.feedback = NewFeedbackLoop(cfg.FeedbackConfig)
		e.feedback.StartCleanup()
		logrus.WithFields(logrus.Fields{
			"initial_threshold": cfg.FeedbackConfig.InitialThreshold,
			"target_fp_rate":    cfg.FeedbackConfig.TargetFPRate,
			"min_threshold":     cfg.FeedbackConfig.MinThreshold,
			"max_threshold":     cfg.FeedbackConfig.MaxThreshold,
		}).Info("Feedback loop enabled - adaptive threshold adjustment active")
	}

	// Attempt to load persisted state
	e.loadState()
	return e
}

// RegisterDetectionHandler adds a handler for detection events
func (e *Engine) RegisterDetectionHandler(handler DetectionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.detectionHandlers = append(e.detectionHandlers, handler)
}

// GetDetectionHandlers returns a copy of registered detection handlers
func (e *Engine) GetDetectionHandlers() []DetectionHandler {
	e.mu.RLock()
	defer e.mu.RUnlock()
	handlers := make([]DetectionHandler, len(e.detectionHandlers))
	copy(handlers, e.detectionHandlers)
	return handlers
}

// StoreVerifiedBotObservation stores a verified legitimate bot observation in the detection cache
func (e *Engine) StoreVerifiedBotObservation(event *DetectionEvent) {
	e.detectionsMu.Lock()
	defer e.detectionsMu.Unlock()

	if event.IP != nil {
		e.latestDetections["ip:"+event.IP.String()] = event
	}
	if event.ASN != "" {
		e.latestDetections["asn:"+event.ASN] = event
	}
	if event.JA4H != "" {
		e.latestDetections["ja4h:"+event.JA4H] = event
	}

	// Also add to history
	e.historyMu.Lock()
	defer e.historyMu.Unlock()

	eventCopy := *event
	e.detectionHistory = append(e.detectionHistory, &eventCopy)

	// Trim history if too large
	if len(e.detectionHistory) > e.historyMaxSize {
		e.detectionHistory = e.detectionHistory[len(e.detectionHistory)-e.historyMaxSize:]
	}
}

// SetThreatIntel sets or updates the threat intelligence provider
func (e *Engine) SetThreatIntel(ti *threatintel.ThreatIntelligence) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threatIntel = ti
}

// RecordFalsePositive records a false positive detection for adaptive learning
func (e *Engine) RecordFalsePositive(ip net.IP, asn string, confidence float64, category BotCategory, wasBlocked bool) {
	if e.feedback == nil {
		return
	}
	e.feedback.RecordFalsePositive(ip.String(), asn, confidence, category, wasBlocked)

	// Retrain ML model with this false positive (it's actually human traffic)
	if e.mlModel != nil {
		// Get the detection to extract its features
		det := e.GetLatestDetection("ip:" + ip.String())
		if det != nil {
			// Extract ML features from the detection
			mlFeatures := e.extractMLFeatures(
				det.Signals,
				det.SignalBreakdown,
				det.SourceBreakdown,
				nil, // behavioral profile
				0,   // reputation score
			)
			// Train model: this pattern is NOT a bot (label = false)
			_ = e.mlModel.Train(mlFeatures, false)

			logrus.WithFields(logrus.Fields{
				"ip":         ip.String(),
				"category":   category,
				"confidence": confidence,
			}).Info("Retrained ML model on false positive - pattern learned as legitimate")
		}
	}
}

// RecordTruePositive records a true positive detection for adaptive learning
func (e *Engine) RecordTruePositive(ip net.IP, asn string, confidence float64, category BotCategory, wasBlocked bool) {
	if e.feedback == nil {
		return
	}
	e.feedback.RecordTruePositive(ip.String(), asn, confidence, category, wasBlocked)

	// Retrain ML model with this true positive (confirmed bot)
	if e.mlModel != nil {
		// Get the detection to extract its features
		det := e.GetLatestDetection("ip:" + ip.String())
		if det != nil {
			// Extract ML features from the detection
			mlFeatures := e.extractMLFeatures(
				det.Signals,
				det.SignalBreakdown,
				det.SourceBreakdown,
				nil, // behavioral profile
				0,   // reputation score
			)
			// Train model: this pattern IS a bot (label = true)
			_ = e.mlModel.Train(mlFeatures, true)

			logrus.WithFields(logrus.Fields{
				"ip":         ip.String(),
				"category":   category,
				"confidence": confidence,
			}).Debug("Retrained ML model on true positive - pattern reinforced as bot")
		}
	}
}

// GetFeedbackStats returns feedback loop statistics
func (e *Engine) GetFeedbackStats() map[string]interface{} {
	if e.feedback == nil {
		return map[string]interface{}{"enabled": false}
	}
	stats := e.feedback.GetStatistics()
	stats["enabled"] = true

	// Add ML tier distribution stats
	mlTierStats := e.getMLTierStats()
	stats["ml_tier_pattern"] = mlTierStats["pattern"]
	stats["ml_tier_onnx"] = mlTierStats["onnx"]
	stats["ml_tier_statistical"] = mlTierStats["statistical"]
	stats["ml_tier_pattern_pct"] = mlTierStats["pattern_pct"]
	stats["ml_tier_onnx_pct"] = mlTierStats["onnx_pct"]
	stats["ml_tier_statistical_pct"] = mlTierStats["statistical_pct"]

	return stats
}

// trackMLTier records which ML tier was used for the last 1000 predictions
func (e *Engine) trackMLTier(tier string) {
	e.mlTierHistoryMu.Lock()
	defer e.mlTierHistoryMu.Unlock()

	// Add to history
	e.mlTierHistory = append(e.mlTierHistory, tier)

	// Keep only last 1000
	if len(e.mlTierHistory) > 1000 {
		// Remove oldest from counts
		oldest := e.mlTierHistory[0]
		if e.mlTierCounts[oldest] > 0 {
			e.mlTierCounts[oldest]--
		}
		e.mlTierHistory = e.mlTierHistory[1:]
	}

	// Increment count
	e.mlTierCounts[tier]++
}

// getMLTierStats returns ML tier distribution
func (e *Engine) getMLTierStats() map[string]interface{} {
	e.mlTierHistoryMu.Lock()
	defer e.mlTierHistoryMu.Unlock()

	total := len(e.mlTierHistory)
	if total == 0 {
		return map[string]interface{}{
			"pattern":         0,
			"onnx":            0,
			"statistical":     0,
			"pattern_pct":     0.0,
			"onnx_pct":        0.0,
			"statistical_pct": 0.0,
		}
	}

	patternCount := e.mlTierCounts["pattern"]
	onnxCount := e.mlTierCounts["onnx"]
	statisticalCount := e.mlTierCounts["statistical"]

	return map[string]interface{}{
		"pattern":         patternCount,
		"onnx":            onnxCount,
		"statistical":     statisticalCount,
		"pattern_pct":     float64(patternCount) / float64(total) * 100,
		"onnx_pct":        float64(onnxCount) / float64(total) * 100,
		"statistical_pct": float64(statisticalCount) / float64(total) * 100,
	}
}

// GetAllowlist returns all IPs currently in the feedback allowlist
func (e *Engine) GetAllowlist() []AllowlistEntry {
	if e.feedback == nil {
		return []AllowlistEntry{}
	}
	return e.feedback.GetAllowlist()
}

// RemoveFromAllowlist removes an IP from the allowlist
func (e *Engine) RemoveFromAllowlist(ip string) {
	if e.feedback != nil {
		e.feedback.RemoveFromAllowlist(ip)
	}
}

// LearnPattern stores a traffic pattern (user-agent, ASN, JA4H) as learned
func (e *Engine) LearnPattern(userAgent, asn, ja4h, label string, labeledByUser bool, notes string) {
	if e.feedback != nil {
		e.feedback.LearnPattern(userAgent, asn, ja4h, label, labeledByUser, notes)
	}
}

// LearnPatternWithBehavior stores a traffic pattern with behavioral signatures
func (e *Engine) LearnPatternWithBehavior(userAgent, asn, ja4h, label string, labeledByUser bool, notes string,
	pathDiversity float64, requestRate float64, hasPathPattern bool, hasTCPPattern bool, hasUDPPattern bool, signalTypes []string) {
	if e.feedback != nil {
		e.feedback.LearnPatternWithBehavior(userAgent, asn, ja4h, label, labeledByUser, notes,
			pathDiversity, requestRate, hasPathPattern, hasTCPPattern, hasUDPPattern, signalTypes)
	}
}

// CheckPattern checks if traffic matches a learned pattern
func (e *Engine) CheckPattern(userAgent, asn, ja4h string) (bool, string, float64, string) {
	if e.feedback != nil {
		return e.feedback.CheckPattern(userAgent, asn, ja4h)
	}
	return false, "", 0.0, ""
}

// GetLearnedPatterns returns all learned patterns
func (e *Engine) GetLearnedPatterns() []LearnedPattern {
	if e.feedback != nil {
		return e.feedback.GetLearnedPatterns()
	}
	return []LearnedPattern{}
}

// RemovePattern removes a learned pattern
func (e *Engine) RemovePattern(key string) {
	if e.feedback != nil {
		e.feedback.RemovePattern(key)
	}
}

// GetFeedbackLoop returns the feedback loop (for hybrid model integration)
func (e *Engine) GetFeedbackLoop() *FeedbackLoop {
	return e.feedback
}

// Start begins processing signals
func (e *Engine) Start() {
	logrus.WithFields(logrus.Fields{
		"workers":     e.workers,
		"buffer_size": cap(e.signalChan),
	}).Info("Starting AI Detection Engine")

	metrics.AIEngineWarmup.Set(1)
	for i := 0; i < e.workers; i++ {
		go e.worker(i)
	}

	// Start ASN maps cleanup
	go e.asnCleanupLoop()

	// Start state save loop
	go e.stateSaveLoop()

	// Warmup watcher
	go func() {
		time.Sleep(e.warmupPeriod)
		metrics.AIEngineWarmup.Set(0)
	}()
}

// Stop shuts down the engine
func (e *Engine) Stop() {
	close(e.stop)
	e.saveState()
}

// SetMLModel allows replacing the ML model after initialization
func (e *Engine) SetMLModel(model MLModel) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mlModel = model
	logrus.Info("ML model replaced")
}

// GetMLModel returns the current ML model
func (e *Engine) GetMLModel() MLModel {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mlModel
}

// EmitSignal sends a signal to the detection engine
func (e *Engine) EmitSignal(signal Signal) {
	if signal.Timestamp.IsZero() {
		signal.Timestamp = time.Now()
	}

	select {
	case e.signalChan <- signal:
		metrics.AIEngineQueueDepth.Set(float64(len(e.signalChan)))
	default:
		metrics.AIEngineQueueDrops.Inc()
		// Rate-limit buffer full warnings to once per 5 seconds
		e.bufferWarningMu.Lock()
		now := time.Now()
		if now.Sub(e.lastBufferWarning) > 5*time.Second {
			e.lastBufferWarning = now
			e.bufferWarningMu.Unlock()
			logrus.WithField("queue_depth", len(e.signalChan)).Warn("AI Detection signal buffer full, dropping signals")
		} else {
			e.bufferWarningMu.Unlock()
		}
	}
}

// worker processes signals from the channel
func (e *Engine) worker(id int) {
	windowSignals := make(map[string][]Signal)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stop:
			return

		case signal := <-e.signalChan:
			e.processSignal(signal, windowSignals)

		case <-ticker.C:
			e.evaluateCampaigns()
			e.evaluateWindow(windowSignals)
			windowSignals = make(map[string][]Signal)
		}
	}
}

// processSignal handles a single signal
// ASN tracking helpers
func (e *Engine) markASNActive(asn, org string, ip net.IP) {
	if asn == "" || asn == "Unknown" || ip == nil {
		return
	}
	e.asnMapsMu.Lock()
	defer e.asnMapsMu.Unlock()
	ipStr := ip.String()
	if e.asnActiveIPs[asn] == nil {
		e.asnActiveIPs[asn] = make(map[string]time.Time)
	}
	e.asnOrg[asn] = org
	e.asnActiveIPs[asn][ipStr] = time.Now()
	active := len(e.asnActiveIPs[asn])
	abusive := len(e.asnAbusiveIPs[asn])
	ratio := 0.0
	if active > 0 {
		ratio = float64(abusive) / float64(active)
	}
	metrics.ASNActiveIPs.WithLabelValues(asn, org).Set(float64(active))
	metrics.ASNAbusiveIPs.WithLabelValues(asn, org).Set(float64(abusive))
	metrics.ASNAbuseRatio.WithLabelValues(asn, org).Set(ratio)
}

func (e *Engine) markASNAbusive(asn, org string, ip net.IP) {
	if asn == "" || asn == "Unknown" || ip == nil {
		return
	}
	e.asnMapsMu.Lock()
	defer e.asnMapsMu.Unlock()
	ipStr := ip.String()
	if e.asnAbusiveIPs[asn] == nil {
		e.asnAbusiveIPs[asn] = make(map[string]time.Time)
	}
	e.asnOrg[asn] = org
	e.asnAbusiveIPs[asn][ipStr] = time.Now()
	// Ensure active map also tracks this IP
	if e.asnActiveIPs[asn] == nil {
		e.asnActiveIPs[asn] = make(map[string]time.Time)
	}
	if _, ok := e.asnActiveIPs[asn][ipStr]; !ok {
		e.asnActiveIPs[asn][ipStr] = time.Now()
	}
	active := len(e.asnActiveIPs[asn])
	abusive := len(e.asnAbusiveIPs[asn])
	ratio := 0.0
	if active > 0 {
		ratio = float64(abusive) / float64(active)
	}
	metrics.ASNActiveIPs.WithLabelValues(asn, org).Set(float64(active))
	metrics.ASNAbusiveIPs.WithLabelValues(asn, org).Set(float64(abusive))
	metrics.ASNAbuseRatio.WithLabelValues(asn, org).Set(ratio)
}

func (e *Engine) getASNRatio(asn string) float64 {
	e.asnMapsMu.Lock()
	defer e.asnMapsMu.Unlock()
	active := len(e.asnActiveIPs[asn])
	if active == 0 {
		return 0
	}
	return float64(len(e.asnAbusiveIPs[asn])) / float64(active)
}

func (e *Engine) cleanupASNMaps() {
	e.asnMapsMu.Lock()
	defer e.asnMapsMu.Unlock()
	now := time.Now()
	for asn, m := range e.asnActiveIPs {
		for ip, ts := range m {
			if now.Sub(ts) > e.asnTTL {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(e.asnActiveIPs, asn)
		}
	}
	for asn, m := range e.asnAbusiveIPs {
		for ip, ts := range m {
			if now.Sub(ts) > e.asnTTL {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(e.asnAbusiveIPs, asn)
		}
	}
	// Update metrics
	for asn, activeMap := range e.asnActiveIPs {
		active := len(activeMap)
		abusive := len(e.asnAbusiveIPs[asn])
		ratio := 0.0
		if active > 0 {
			ratio = float64(abusive) / float64(active)
		}
		org := e.asnOrg[asn]
		if org == "" {
			org = "Unknown"
		}
		metrics.ASNActiveIPs.WithLabelValues(asn, org).Set(float64(active))
		metrics.ASNAbusiveIPs.WithLabelValues(asn, org).Set(float64(abusive))
		metrics.ASNAbuseRatio.WithLabelValues(asn, org).Set(ratio)
	}
}

func (e *Engine) asnCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-ticker.C:
			e.cleanupASNMaps()
		}
	}
}

type asnState struct {
	Active  map[string]map[string]time.Time `json:"active"`
	Abusive map[string]map[string]time.Time `json:"abusive"`
	Org     map[string]string               `json:"org"`
}

func (e *Engine) asnPenaltyScale(asn string) float64 {
	ratio := e.getASNRatio(asn)
	switch {
	case ratio <= 0.005:
		return 0.25
	case ratio <= 0.01:
		return 0.4
	case ratio <= 0.05:
		return 0.7
	case ratio <= 0.10:
		return 1.0
	case ratio <= 0.20:
		return 1.2
	case ratio <= 0.50:
		return 1.5
	default:
		return 2.0
	}
}

func (e *Engine) loadState() {
	if e.statePath == "" {
		return
	}
	data, err := os.ReadFile(e.statePath)
	if err != nil {
		return
	}
	var st asnState
	if err := json.Unmarshal(data, &st); err != nil {
		logrus.WithError(err).Warn("Failed to unmarshal ASN state")
		return
	}
	e.asnMapsMu.Lock()
	defer e.asnMapsMu.Unlock()
	// hydrate maps, drop expired
	now := time.Now()
	for asn, m := range st.Active {
		for ip, ts := range m {
			if now.Sub(ts) <= e.asnTTL {
				if e.asnActiveIPs[asn] == nil {
					e.asnActiveIPs[asn] = make(map[string]time.Time)
				}
				e.asnActiveIPs[asn][ip] = ts
			}
		}
	}
	for asn, m := range st.Abusive {
		for ip, ts := range m {
			if now.Sub(ts) <= e.asnTTL {
				if e.asnAbusiveIPs[asn] == nil {
					e.asnAbusiveIPs[asn] = make(map[string]time.Time)
				}
				e.asnAbusiveIPs[asn][ip] = ts
			}
		}
	}
	for asn, org := range st.Org {
		e.asnOrg[asn] = org
	}
	logrus.WithFields(logrus.Fields{"active_asn": len(e.asnActiveIPs), "abusive_asn": len(e.asnAbusiveIPs)}).Info("Loaded ASN state")
}

func (e *Engine) saveState() {
	if e.statePath == "" {
		return
	}
	e.asnMapsMu.Lock()
	st := asnState{
		Active:  make(map[string]map[string]time.Time),
		Abusive: make(map[string]map[string]time.Time),
		Org:     make(map[string]string),
	}
	now := time.Now()
	for asn, m := range e.asnActiveIPs {
		for ip, ts := range m {
			if now.Sub(ts) <= e.asnTTL {
				if st.Active[asn] == nil {
					st.Active[asn] = make(map[string]time.Time)
				}
				st.Active[asn][ip] = ts
			}
		}
	}
	for asn, m := range e.asnAbusiveIPs {
		for ip, ts := range m {
			if now.Sub(ts) <= e.asnTTL {
				if st.Abusive[asn] == nil {
					st.Abusive[asn] = make(map[string]time.Time)
				}
				st.Abusive[asn][ip] = ts
			}
		}
	}
	for asn, org := range e.asnOrg {
		st.Org[asn] = org
	}
	e.asnMapsMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(e.statePath), 0o755); err != nil {
		logrus.WithError(err).Warn("Failed to create state dir")
		return
	}
	buf, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		logrus.WithError(err).Warn("Failed to marshal ASN state")
		return
	}
	tmp := e.statePath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		logrus.WithError(err).Warn("Failed to write ASN state tmp")
		return
	}
	if err := os.Rename(tmp, e.statePath); err != nil {
		logrus.WithError(err).Warn("Failed to rename ASN state")
	}
}

func (e *Engine) stateSaveLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-e.stop:
			e.saveState()
			return
		case <-ticker.C:
			e.saveState()
		}
	}
}

func (e *Engine) processSignal(signal Signal, windowSignals map[string][]Signal) {
	start := time.Now()
	defer func() {
		metrics.AISignalProcessingLatency.Observe(time.Since(start).Seconds())
	}()

	signal.Type = CanonicalizeSignalType(signal.Type)

	// Capture pre-detection event for potential session recording
	if signal.IP != nil {
		ipStr := signal.IP.String()

		// Check if IP is in learning window before acquiring pre-detection lock
		if e.feedback != nil && e.feedback.IsInLearningWindow(ipStr) {
			e.capturePreDetectionEvent(ipStr, signal)
		}

		// Only capture post-detection if recording is actually active (single lock acquisition)
		e.sessionRecordingsMu.Lock()
		if e.sessionRecordings[ipStr] != nil {
			e.capturePostDetectionEventLocked(ipStr, signal)
		}
		e.sessionRecordingsMu.Unlock()
	}

	// Lookup ASN/Org if missing
	if e.geoip != nil && signal.IP != nil && (signal.ASN == "" || signal.Org == "" || signal.Org == "unknown") {
		asn, org := e.geoip.Lookup(signal.IP)
		if signal.ASN == "" {
			signal.ASN = asn
		}
		if signal.Org == "" || signal.Org == "unknown" {
			signal.Org = org
		}
	}

	if e.campaigns != nil {
		e.campaigns.Record(signal)
		metrics.ActiveAttackCampaigns.Set(float64(e.campaigns.ActiveCampaigns(time.Now())))
	}

	// Add signal to event history for advanced feature extraction
	if signal.IP != nil && e.historyManager != nil {
		event := SignalEvent{
			Type:      signal.Type,
			Source:    signal.Source,
			Timestamp: signal.Timestamp,
			Metadata:  signal.Metadata,
		}
		e.historyManager.AddEvent(signal.IP.String(), event)
	}

	metrics.AISignalsTotal.Inc()
	metrics.AISignalsByType.WithLabelValues(string(signal.Type)).Inc()
	metrics.AISignalsBySource.WithLabelValues(string(signal.Source)).Inc()

	// Increment specific metrics for certain signal types
	switch signal.Type {
	case SignalProxyLag:
		// Proxy lag detection
		if lag, ok := signal.Metadata["proxy_lag_ms"].(float64); ok {
			metrics.HighestProxyLagMs.Set(lag)
		}
	case SignalJA4TAbuse:
		metrics.JA4TSuspiciousEvents.Inc()
	case SignalHighLatency:
		metrics.HighLatencyEvents.Inc()
	case SignalLatencyMismatch:
		metrics.LatencyMismatchEvents.Inc()
	}

	asnTag := signal.ASN
	orgTag := signal.Org
	if asnTag == "" {
		asnTag = "Unknown"
	}
	if orgTag == "" {
		orgTag = "Unknown"
	}
	metrics.AISignalsByASN.WithLabelValues(asnTag, orgTag, string(signal.Type)).Inc()
	// Track active IPs per ASN for proportional scaling
	e.markASNActive(asnTag, orgTag, signal.IP)

	if e.reputation != nil && signal.IP != nil {
		weight := signal.Weight
		if weight == 0 {
			weight = 5.0
		}
		if signal.Type == SignalIncompleteHandshake && weight > 20 {
			weight = 20
		}
		e.reputation.Penalize(signal.IP.String(), reputation.TypeIP, weight, string(signal.Type))

		lowSeverityASN := map[SignalType]bool{
			SignalMissingAcceptLang:   true,
			SignalMissingAcceptEnc:    true,
			SignalNoCookies:           true,
			SignalNoReferer:           true,
			SignalProxyLag:            true,
			SignalHighLatency:         true,
			SignalLatencyMismatch:     true,
			SignalIncompleteHandshake: true,
			SignalHeaderOrderAnomaly:  true,
			SignalMissingSecCH:        true,
		}

		if signal.ASN != "" && signal.ASN != "Unknown" {
			e.reputation.ObserveIP(signal.ASN, signal.IP.String())
			asnWeight := weight * 0.25
			if lowSeverityASN[signal.Type] {
				asnWeight = weight * 0.1
			}
			e.reputation.PenalizeASN(signal.ASN, signal.IP.String(), asnWeight, string(signal.Type))
		}

		if signal.JA4H != "" {
			e.reputation.Penalize(signal.JA4H, reputation.TypeJA4, weight*0.6, string(signal.Type))
		}
	}

	e.metricsMu.Lock()
	if signal.IP != nil {
		ipStr := signal.IP.String()
		e.signalsByIP[ipStr]++
		if e.signalTypesByIP[ipStr] == nil {
			e.signalTypesByIP[ipStr] = make(map[string]uint64)
		}
		e.signalTypesByIP[ipStr][string(signal.Type)]++
		if e.signalSourcesByIP[ipStr] == nil {
			e.signalSourcesByIP[ipStr] = make(map[string]uint64)
		}
		e.signalSourcesByIP[ipStr][string(signal.Source)]++
	}
	if signal.ASN != "" {
		e.signalsByASN[signal.ASN]++
		if e.signalTypesByASN[signal.ASN] == nil {
			e.signalTypesByASN[signal.ASN] = make(map[string]uint64)
		}
		e.signalTypesByASN[signal.ASN][string(signal.Type)]++
		if e.signalSourcesByASN[signal.ASN] == nil {
			e.signalSourcesByASN[signal.ASN] = make(map[string]uint64)
		}
		e.signalSourcesByASN[signal.ASN][string(signal.Source)]++
	}
	if signal.JA4H != "" {
		e.signalsByJA4H[signal.JA4H]++
		if e.signalTypesByJA4H[signal.JA4H] == nil {
			e.signalTypesByJA4H[signal.JA4H] = make(map[string]uint64)
		}
		e.signalTypesByJA4H[signal.JA4H][string(signal.Type)]++
		if e.signalSourcesByJA4H[signal.JA4H] == nil {
			e.signalSourcesByJA4H[signal.JA4H] = make(map[string]uint64)
		}
		e.signalSourcesByJA4H[signal.JA4H][string(signal.Source)]++
	}
	e.metricsMu.Unlock()

	key := ""
	if signal.JA4H != "" {
		key = "ja4h:" + signal.JA4H
	} else if signal.IP != nil {
		key = "ip:" + signal.IP.String()
	} else {
		return
	}

	windowSignals[key] = append(windowSignals[key], signal)

	// Update behavioral profile
	signalTypes := make(map[SignalType]bool)
	sources := make(map[SignalSource]bool)
	for _, s := range windowSignals[key] {
		signalTypes[s.Type] = true
		sources[s.Source] = true
	}
	e.updateBehavioralProfile(key, signal, signalTypes, sources)

	logrus.WithFields(logrus.Fields{
		"type":   signal.Type,
		"source": signal.Source,
		"ip":     signal.IP,
		"ja4h":   signal.JA4H,
		"asn":    signal.ASN,
		"weight": signal.Weight,
	}).Debug("AI Signal Received")
}

func (e *Engine) evaluateCampaigns() {
	if e.campaigns == nil {
		return
	}
	detections := e.campaigns.Evaluate(time.Now())
	metrics.ActiveAttackCampaigns.Set(float64(e.campaigns.ActiveCampaigns(time.Now())))
	for _, detection := range detections {
		e.handleCampaignDetection(detection)
	}
}

func (e *Engine) handleCampaignDetection(detection CampaignDetection) {
	vector := string(detection.Vector)
	reason := detection.Reason
	if vector == "" {
		vector = "unknown"
	}
	if reason == "" {
		reason = "unknown"
	}

	metrics.AttackCampaignDetections.WithLabelValues(vector, reason).Inc()
	metrics.CarpetBombingDetections.WithLabelValues(vector, reason).Inc()

	metadata := map[string]interface{}{
		"campaign_id":       detection.ID,
		"campaign_key":      detection.Key,
		"campaign_reason":   detection.Reason,
		"campaign_vector":   string(detection.Vector),
		"dest_ips":          detection.DestinationIPs,
		"dest_subnets":      detection.DestSubnets,
		"dest_ports":        detection.DestinationPorts,
		"source_ips":        detection.SourceIPs,
		"asns":              detection.ASNs,
		"collectors":        detection.Collectors,
		"source_kinds":      detection.SourceKinds,
		"total_weight":      detection.TotalWeight,
		"observe_only":      true,
		"enforcement_scope": "none",
	}

	event := DetectionEvent{
		IP:            detection.SampleIP,
		DestIP:        detection.SampleDestIP,
		DstPort:       detection.SampleDstPort,
		ASN:           detection.SampleASN,
		Org:           detection.SampleOrg,
		Signals:       []Signal{{Type: SignalCarpetBombing, Source: SourceTCP, IP: detection.SampleIP, Weight: detection.TotalWeight, Timestamp: detection.LastSeen, Metadata: metadata}},
		SignalCount:   detection.SignalCount,
		DetectionTime: detection.LastSeen,
		Confidence:    0.65,
		Score:         detection.TotalWeight,
		BotCategory:   BotCategoryDDoS,
		BlockReason: fmt.Sprintf(
			"Attack campaign observed (%s): %d signals across %d destinations, %d ports, %d sources",
			detection.Reason,
			detection.SignalCount,
			detection.DestinationIPs,
			detection.DestinationPorts,
			detection.SourceIPs,
		),
		WouldBlock:      false,
		SignalBreakdown: map[SignalType]int{SignalCarpetBombing: detection.SignalCount},
		SourceBreakdown: map[SignalSource]int{SourceTCP: 1},
		Reasons:         []string{"campaign:" + detection.Reason},
		Metadata:        metadata,
	}

	e.detectionsMu.Lock()
	e.latestDetections["campaign:"+detection.ID] = &event
	e.detectionsMu.Unlock()

	e.historyMu.Lock()
	eventCopy := event
	e.detectionHistory = append(e.detectionHistory, &eventCopy)
	if len(e.detectionHistory) > e.historyMaxSize {
		e.detectionHistory = e.detectionHistory[len(e.detectionHistory)-e.historyMaxSize:]
	}
	e.historyMu.Unlock()

	logrus.WithFields(logrus.Fields{
		"component":    "aidetection_engine",
		"event":        "attack_campaign_observed",
		"campaign_id":  detection.ID,
		"vector":       vector,
		"reason":       reason,
		"signal_count": detection.SignalCount,
		"dest_ips":     detection.DestinationIPs,
		"dest_subnets": detection.DestSubnets,
		"dest_ports":   detection.DestinationPorts,
		"source_ips":   detection.SourceIPs,
		"total_weight": detection.TotalWeight,
		"observe_only": true,
	}).Info("Attack campaign observed")
}

// evaluateWindow checks if accumulated signals trigger a detection
func (e *Engine) evaluateWindow(windowSignals map[string][]Signal) {
	lowSeverity := map[SignalType]bool{
		SignalWindowAnomaly:       true,
		SignalIncompleteHandshake: true,
		SignalHighLatency:         true,
		SignalLatencyMismatch:     true,
		SignalProxyLag:            true,
		SignalBrowserDetected:     true,
		SignalTCPMetadata:         true,
		SignalMissingAcceptLang:   true,
	}
	highSeverity := map[SignalType]bool{
		SignalHoneypot:          true,
		SignalNumericSequence:   true,
		SignalAlphaSequence:     true,
		SignalJA4TAbuse:         true,
		SignalHighFrequency:     true,
		SignalConnectionPattern: true,
		SignalPortScanning:      true,
		SignalGeoAnomaly:        true,
		SignalTimingPattern:     true,
		SignalICMPFlood:         true,
		SignalUDPFlood:          true,
		SignalSYNFlood:          true,
		SignalBadFlags:          true,
		SignalJA4HBotMatch:      true,
		SignalKnownScanner:      true,
	}

	floodWeightByASN := make(map[string]float64)
	for _, signals := range windowSignals {
		for _, sig := range signals {
			if sig.Type == SignalICMPFlood || sig.Type == SignalUDPFlood || sig.Type == SignalSYNFlood || sig.Type == SignalBadFlags || sig.Type == SignalIncompleteHandshake {
				asn := sig.ASN
				if asn == "" {
					continue
				}
				floodWeightByASN[asn] += sig.Weight
			}
		}
	}

	for key, signals := range windowSignals {
		if len(signals) == 0 {
			continue
		}

		uniqueTypes := make(map[SignalType]struct{})
		totalWeight := 0.0
		lowOnly := true
		countIncomplete := 0
		hasHigh := false
		floodWeight := 0.0
		sources := make(map[SignalSource]struct{})
		for _, sig := range signals {
			uniqueTypes[sig.Type] = struct{}{}
			sources[sig.Source] = struct{}{}
			if sig.Type == SignalIncompleteHandshake {
				countIncomplete++
			}
			if !lowSeverity[sig.Type] {
				lowOnly = false
			}
			if highSeverity[sig.Type] {
				hasHigh = true
			}
			if sig.Type == SignalICMPFlood || sig.Type == SignalUDPFlood || sig.Type == SignalSYNFlood || sig.Type == SignalBadFlags {
				floodWeight += sig.Weight
			}
			w := sig.Weight
			if w == 0 {
				w = 1.0
			}
			totalWeight += w
		}
		uniqueTypeCount := len(uniqueTypes)
		sourceCount := len(sources)
		score := totalWeight
		asnFloodWeight := 0.0
		if first := signals[0]; first.ASN != "" {
			asnFloodWeight = floodWeightByASN[first.ASN]
		}
		ddos, _ := e.isDDoSPattern(signals, asnFloodWeight)

		// Guard: low-severity only combos need more evidence
		if !ddos && lowOnly {
			if countIncomplete < 5 && len(signals) < 4 {
				continue
			}
		}
		// Guard: at least 3 signals or a high-severity present (unless ddos)
		if !ddos && len(signals) < 3 && !hasHigh {
			continue
		}
		// Guard: weak flood signals should be ignored
		if !ddos && floodWeight > 0 && floodWeight < e.ddosMinFloodWeight {
			continue
		}
		// Guard: require minimal score for suspicion
		if !ddos && score < e.suspiciousScoreThreshold {
			continue
		}
		// Guard: require at least 2 unique types AND >1 source for low-severity only
		if !ddos && lowOnly && sourceCount < 2 {
			continue
		}

		detected := false
		ewmaBaseline := 0.0
		confidence := 0.5

		switch {
		case ddos:
			detected = true
			confidence = 0.9
		case uniqueTypeCount >= 2 && (len(signals) >= e.staticThreshold || totalWeight >= float64(e.staticThreshold)):
			detected = true
			confidence = 0.8
		case uniqueTypeCount >= 2:
			detected, ewmaBaseline = e.checkAdaptiveDetection(key, len(signals))
			if detected {
				confidence = 0.6
			}
		}

		if detected {
			e.handleDetection(key, signals, ewmaBaseline, confidence, asnFloodWeight)
		}
	}
}

// isDDoSPattern returns true for clear DDoS indicators (e.g., SYN flood via incomplete handshakes)
func (e *Engine) isDDoSPattern(signals []Signal, asnFloodWeight float64) (bool, map[string]interface{}) {
	if !e.enableDDoSCategory {
		return false, nil
	}

	countIncomplete := 0
	countConnPattern := 0
	countHighFreq := 0
	countTiming := 0
	hasFlood := false
	floodWeight := 0.0
	sourceCounts := make(map[SignalSource]int)

	for _, sig := range signals {
		sourceCounts[sig.Source]++
		switch sig.Type {
		case SignalIncompleteHandshake:
			countIncomplete++
			hasFlood = true
			w := sig.Weight
			if w == 0 {
				w = 1
			}
			floodWeight += w
		case SignalConnectionPattern:
			countConnPattern++
		case SignalHighFrequency:
			countHighFreq++
		case SignalTimingPattern:
			countTiming++
		case SignalUDPFlood, SignalICMPFlood, SignalSYNFlood, SignalBadFlags:
			hasFlood = true
			w := sig.Weight
			if w == 0 {
				w = 1
			}
			floodWeight += w
		}
	}

	onlySPOE := len(sourceCounts) == 1 && sourceCounts[SourceSPOE] > 0
	patternCount := countConnPattern + countHighFreq + countTiming
	requireFreq := e.ddosRequireHighFreq

	// Guard: HTTP-only signals (SPOE) should not trigger DDoS unless flood/incomplete thresholds hit
	if onlySPOE && !hasFlood && countIncomplete < e.ddosIncompleteThreshold && patternCount < e.ddosPatternThreshold && len(signals) < e.ddosTotalThreshold {
		return false, nil
	}

	// Require heavy flood (per IP or per ASN) for DDoS classification
	if !(floodWeight >= e.ddosMinIPFloodPPS || asnFloodWeight >= e.ddosMinASNFloodPPS) {
		return false, nil
	}

	info := map[string]interface{}{
		"count_incomplete": countIncomplete,
		"pattern_count":    patternCount,
		"total":            len(signals),
		"sources":          sourceCounts,
		"require_freq":     requireFreq,
		"flood_weight":     floodWeight,
		"asn_flood_weight": asnFloodWeight,
		"thresholds": map[string]int{
			"incomplete": e.ddosIncompleteThreshold,
			"pattern":    e.ddosPatternThreshold,
			"total":      e.ddosTotalThreshold,
		},
	}

	// Thresholds tuned for 10s window; conservative defaults
	ddosReason := func(reason string) string {
		if floodWeight < e.ddosMinIPFloodPPS && asnFloodWeight >= e.ddosMinASNFloodPPS {
			return "distributed_asn_" + reason
		}
		return reason
	}

	if countIncomplete >= e.ddosIncompleteThreshold {
		if !requireFreq || countHighFreq > 0 || hasFlood {
			info["ddos_reason"] = ddosReason("incomplete")
			logrus.WithFields(info).Debug("DDoS pattern matched")
			return true, info
		}
	}

	if patternCount >= e.ddosPatternThreshold {
		if !requireFreq || countHighFreq > 0 || hasFlood {
			info["ddos_reason"] = ddosReason("pattern")
			logrus.WithFields(info).Debug("DDoS pattern matched")
			return true, info
		}
	}

	// Fallback: extreme signal volume triggers ddos classification
	if len(signals) >= e.ddosTotalThreshold {
		if (!requireFreq || patternCount > 0) && (floodWeight >= e.ddosMinIPFloodPPS || asnFloodWeight >= e.ddosMinASNFloodPPS) {
			info["ddos_reason"] = ddosReason("volume")
			logrus.WithFields(info).Debug("DDoS pattern matched")
			return true, info
		}
	}

	return false, nil
}

// checkAdaptiveDetection uses EWMA baseline to detect anomalies
func (e *Engine) checkAdaptiveDetection(key string, currentCount int) (bool, float64) {
	now := time.Now()
	current := float64(currentCount)

	e.ewmaMu.Lock()
	defer e.ewmaMu.Unlock()

	if len(e.ewmaMap) > 20000 {
		e.ewmaMap = make(map[string]*ewma.State)
	}

	st := e.ewmaMap[key]
	if st == nil {
		st = &ewma.State{Value: current, LastTime: now}
		e.ewmaMap[key] = st
	} else {
		newState := ewma.Update(*st, current, now, e.ewmaTau)
		e.ewmaMap[key] = &newState
		st = &newState
	}

	if st.Value >= e.ewmaMinBaseline && current > st.Value*e.ewmaMultiplier+2 {
		return true, st.Value
	}

	return false, st.Value
}

// handleDetection processes a confirmed detection
func (e *Engine) shouldLogDetection(key string) bool {
	const ttl = 30 * time.Second
	e.logThrottleMu.Lock()
	defer e.logThrottleMu.Unlock()
	now := time.Now()
	if prev, ok := e.logThrottle[key]; ok {
		if now.Sub(prev) < ttl {
			return false
		}
	}
	e.logThrottle[key] = now
	return true
}

const (
	strongRuleConfidenceFloor = 0.80
	legitimateMLConfidenceCap = 0.40
	strongLegitimateMLMinConf = 0.90
	strongLegitimateMLMaxBotP = 0.10
)

func blendMLConfidence(ruleConfidence float64, prediction MLPredictionResult) float64 {
	mlConfidence := clampConfidence(prediction.Confidence)
	ruleConfidence = clampConfidence(ruleConfidence)

	if prediction.IsBot {
		return math.Max(ruleConfidence, mlConfidence)
	}
	if isStrongLegitimateML(prediction) && ruleConfidence < strongRuleConfidenceFloor {
		return math.Min(ruleConfidence, legitimateMLConfidenceCap)
	}
	return ruleConfidence
}

func isStrongLegitimateML(prediction MLPredictionResult) bool {
	return !prediction.IsBot &&
		prediction.Confidence >= strongLegitimateMLMinConf &&
		prediction.BotProbability <= strongLegitimateMLMaxBotP
}

func clampConfidence(confidence float64) float64 {
	if confidence < 0 {
		return 0
	}
	if confidence > 1 {
		return 1
	}
	return confidence
}

func (e *Engine) handleDetection(key string, signals []Signal, ewmaBaseline, confidence, asnFloodWeight float64) {
	if len(signals) == 0 {
		return
	}

	firstSignal := signals[0]

	// Build signal breakdowns
	signalTypes := make(map[SignalType]int)
	signalTypesMap := make(map[SignalType]bool)
	sources := make(map[SignalSource]int)
	sourcesMap := make(map[SignalSource]bool)
	for _, sig := range signals {
		signalTypes[sig.Type]++
		signalTypesMap[sig.Type] = true
		sources[sig.Source]++
		sourcesMap[sig.Source] = true
	}

	// Get user agent and JA4 info from signal metadata
	// Check all signals, not just the first one
	userAgent := ""
	ja4Info := ""
	ja4 := firstSignal.JA4
	ja4h := firstSignal.JA4H
	ja4t := firstSignal.JA4T

	for _, sig := range signals {
		if sig.Metadata == nil {
			continue
		}
		if userAgent == "" {
			if ua, ok := sig.Metadata["user_agent"].(string); ok && ua != "" {
				userAgent = ua
			}
		}
		if ja4Info == "" {
			if info, ok := sig.Metadata["ja4h_info"].(string); ok && info != "" {
				ja4Info = info
			}
		}
		if ja4Info == "" {
			if info, ok := sig.Metadata["ja4_info"].(string); ok && info != "" {
				ja4Info = info
			}
		}
		if ja4 == "" {
			if v, ok := sig.Metadata["ja4"].(string); ok && v != "" {
				ja4 = v
			}
		}
		if ja4h == "" {
			if v, ok := sig.Metadata["ja4h"].(string); ok && v != "" {
				ja4h = v
			}
		}
		if ja4t == "" {
			if v, ok := sig.Metadata["ja4t"].(string); ok && v != "" {
				ja4t = v
			}
		}

		// Stop early if we've found everything
		if userAgent != "" && ja4Info != "" && ja4 != "" && ja4h != "" && ja4t != "" {
			break
		}
	}

	// Check if this traffic pattern has been learned as legitimate
	if e.feedback != nil {
		if matched, label, patternConfidence, patternKey := e.feedback.CheckPattern(userAgent, firstSignal.ASN, ja4h); matched {
			if label == "legitimate" && patternConfidence >= 0.7 {
				// This is a known legitimate pattern - skip detection
				logrus.WithFields(logrus.Fields{
					"key":                key,
					"pattern_key":        patternKey,
					"pattern_confidence": patternConfidence,
					"user_agent":         userAgent,
					"asn":                firstSignal.ASN,
					"ja4h":               ja4h,
				}).Debug("Skipping detection - matched learned legitimate pattern")
				return
			} else if label == "malicious" && patternConfidence >= 0.7 {
				// Known malicious pattern - boost confidence
				confidence = math.Max(confidence, 0.85)
				logrus.WithFields(logrus.Fields{
					"key":                key,
					"pattern_key":        patternKey,
					"pattern_confidence": patternConfidence,
					"boosted_confidence": confidence,
				}).Debug("Boosted confidence - matched learned malicious pattern")
			}
		}
	}

	// Verify crawler if applicable
	verifier := e.crawlerVerifier
	verified := VerificationUnknown
	if firstSignal.IP != nil && userAgent != "" {
		verified = verifier.VerifyCrawler(firstSignal.IP, userAgent)
	}

	// Categorize bot (with JA4/JA4H/JA4T info passed from signal to avoid duplicate lookup)
	botCategory := verifier.CategorizeBot(userAgent, ja4, ja4h, ja4t, ja4Info, signalTypes, sources, verified)

	// Skip browser detections (legitimate clients)
	if botCategory == BotCategoryBrowser {
		logrus.WithFields(logrus.Fields{
			"component": "aidetection_engine",
			"event":     "browser_detected",
			"key":       key,
			"ja4h":      firstSignal.JA4H,
			"ja4":       firstSignal.JA4,
			"ja4t":      firstSignal.JA4T,
			"ua":        userAgent,
		}).Debug("Browser detected, skipping bot detection")
		return
	}

	ddosDetected, ddosInfo := e.isDDoSPattern(signals, asnFloodWeight)
	if !ddosDetected && botCategory == BotCategoryDDoS {
		botCategory = BotCategoryUnknown
	}

	// Guard: unknown category needs higher confidence/volume
	lowSeverity := func() bool {
		low := map[SignalType]bool{
			SignalWindowAnomaly:       true,
			SignalIncompleteHandshake: true,
			SignalHighLatency:         true,
			SignalLatencyMismatch:     true,
			SignalProxyLag:            true,
			SignalTCPMetadata:         true,
			SignalMissingAcceptLang:   true,
		}
		for st := range signalTypes {
			if !low[st] {
				return false
			}
		}
		return true
	}()
	if botCategory == BotCategoryUnknown && !ddosDetected {
		if len(signals) < 3 {
			return
		}
		if lowSeverity && confidence < 0.8 {
			return
		}
		if confidence < 0.6 {
			return
		}
	}

	// Get behavioral profile
	profileKey := key
	if profileKey == "" {
		if firstSignal.JA4H != "" {
			profileKey = "ja4h:" + firstSignal.JA4H
		} else if firstSignal.IP != nil {
			profileKey = "ip:" + firstSignal.IP.String()
		}
	}
	behavioralProfile := e.GetBehavioralProfile(profileKey)

	// Get reputation score
	reputationScore := 0.0
	if e.reputation != nil && firstSignal.IP != nil {
		reputationScore = e.reputation.GetScore(firstSignal.IP.String(), reputation.TypeIP)
	}

	// Compute score (sum of weights, default 1) with per-type caps
	typeCaps := map[SignalType]float64{
		SignalIncompleteHandshake: 6,
		SignalMissingAcceptLang:   1,
		SignalMissingAcceptEnc:    1,
		SignalTCPMetadata:         1,
		SignalWindowAnomaly:       5,
		SignalLatencyMismatch:     2,
		SignalProxyLag:            2,
		SignalHeaderOrderAnomaly:  2,
		SignalMissingSecCH:        2,
		SignalBotUA:               10,
		SignalJA4HBotMatch:        30,
		SignalHoneypot:            30,
		SignalKnownScanner:        50,
		SignalICMPFlood:           50,
		SignalUDPFlood:            50,
		SignalSYNFlood:            50,
	}
	scoreByType := make(map[SignalType]float64)
	score := 0.0
	for _, sig := range signals {
		w := sig.Weight
		if w == 0 {
			w = 1
		}
		cap := typeCaps[sig.Type]
		if cap == 0 {
			cap = 20
		}
		prev := scoreByType[sig.Type]
		add := w
		if prev+add > cap {
			add = cap - prev
			if add < 0 {
				add = 0
			}
		}
		scoreByType[sig.Type] = prev + add
		score += add
	}

	// Calculate enhanced confidence
	enhancedConfidence := CalculateConfidence(
		signals,
		signalTypes,
		sources,
		behavioralProfile,
		verified,
		reputationScore,
		score,
	)

	// Use enhanced confidence instead of basic
	confidence = enhancedConfidence

	if ddosDetected {
		if e.enableDDoSCategory {
			botCategory = BotCategoryDDoS
		}
		if confidence < 0.95 {
			confidence = 0.95
		}
	}

	// Boost confidence with threat intelligence data
	if e.threatIntel != nil && firstSignal.IP != nil {
		enrichedInfo := e.threatIntel.GetEnrichedInfo(firstSignal.IP)
		if enrichedInfo != nil {
			// Known scanner = very high confidence boost
			if enrichedInfo.IsKnownScanner {
				confidence = math.Min(confidence+0.3, 1.0)
				logrus.WithFields(logrus.Fields{
					"ip":                firstSignal.IP.String(),
					"threat_score":      enrichedInfo.ThreatScore,
					"original_conf":     enhancedConfidence,
					"boosted_conf":      confidence,
					"scanner_confirmed": true,
				}).Debug("Threat intel boosted detection confidence")
			} else if enrichedInfo.ThreatScore >= 50 {
				// High threat score = moderate confidence boost
				boost := (enrichedInfo.ThreatScore - 50) / 500.0 // Max 0.1 boost
				confidence = math.Min(confidence+boost, 1.0)
				logrus.WithFields(logrus.Fields{
					"ip":            firstSignal.IP.String(),
					"threat_score":  enrichedInfo.ThreatScore,
					"original_conf": enhancedConfidence,
					"boosted_conf":  confidence,
					"boost_amount":  boost,
				}).Debug("Threat intel boosted detection confidence")
			}

			// Tor/VPN = light confidence boost (anonymization attempts)
			if enrichedInfo.IsTor || enrichedInfo.IsVPN {
				confidence = math.Min(confidence+0.05, 1.0)
			}
		}
	}

	if behavioralProfile != nil && behavioralProfile.IsBursty {
		metrics.BurstDetections.Inc()
	}

	// ML Model Prediction
	var mlConfidence float64
	var mlCategory BotCategory
	var mlModelTier string     // Track which tier was used: "pattern", "onnx", "statistical"
	var ruleConfidence float64 // Store rule-based confidence for display only

	if e.mlModel != nil {
		mlFeatures := e.extractMLFeatures(signals, signalTypes, sources, behavioralProfile, reputationScore)

		// Use ML model for prediction
		prediction := e.mlModel.Predict(mlFeatures)

		mlConfidence = prediction.Confidence
		mlCategory = prediction.Category
		mlModelTier = prediction.ModelTier // Track which tier was used
		if mlCategory == "" {
			mlCategory = BotCategoryUnknown
		}

		ruleConfidence = confidence
		confidence = blendMLConfidence(ruleConfidence, prediction)

		// If ML is highly confident it's legitimate, cap weak/moderate rule
		// confidence to prevent blocking. Strong rule evidence remains a floor.
		if !prediction.IsBot && isStrongLegitimateML(prediction) && ruleConfidence < strongRuleConfidenceFloor {
			logrus.WithFields(logrus.Fields{
				"ip":               firstSignal.IP.String(),
				"ml_confidence":    mlConfidence,
				"rule_confidence":  ruleConfidence,
				"final_confidence": confidence,
			}).Debug("ML model marked traffic as legitimate, reducing confidence")
		}

		// Override category if ML is highly confident
		if prediction.IsBot && mlConfidence > 0.80 {
			botCategory = mlCategory
		}

		// Export ML metrics
		metrics.MLBotProbability.Set(prediction.BotProbability)
		metrics.MLPredictionTotal.Inc()
		metrics.MLPredictionsByCategory.WithLabelValues(string(mlCategory), strconv.FormatBool(prediction.IsBot)).Inc()
		metrics.MLConfidenceByCategory.WithLabelValues(string(mlCategory)).Observe(mlConfidence)
		if prediction.IsBot {
			metrics.MLBotDetections.Inc()
		}
	}

	// Ensure category is not unknown when blocking (derive from signals)
	if botCategory == BotCategoryUnknown {
		if derived := InferCategoryFromSignals(signalTypes); derived != BotCategoryUnknown {
			botCategory = derived
		}
	}

	// Generate detailed block reason
	blockReason := GenerateBlockReason(
		signalTypes,
		sources,
		botCategory,
		verified,
		confidence,
		e.confidenceThreshold,
		enhancedConfidence,
		mlConfidence,
	)

	// Determine if this would actually block
	// Block based on confidence (ML-driven) OR for clear DDoS attacks with high score
	isDDoS := botCategory == BotCategoryDDoS
	wouldBlock := (confidence >= e.confidenceThreshold) || (isDDoS && score >= e.blockScoreThreshold)

	// Extract HTTP context fields from signal metadata
	var hostname, method, path, destIP string
	var dstPort uint32
	for _, sig := range signals {
		if sig.Metadata != nil {
			if h, ok := sig.Metadata["host"].(string); ok && h != "" {
				hostname = h
			}
			if m, ok := sig.Metadata["method"].(string); ok && m != "" {
				method = m
			}
			if p, ok := sig.Metadata["path"].(string); ok && p != "" {
				path = p
			}
			if dip, ok := sig.Metadata["dest_ip"].(string); ok && dip != "" {
				destIP = dip
			}
			if dp, ok := sig.Metadata["dst_port"].(uint32); ok && dp > 0 {
				dstPort = dp
			} else if dp, ok := sig.Metadata["dst_port"].(int64); ok && dp > 0 {
				dstPort = uint32(dp)
			} else if dp, ok := sig.Metadata["dst_port"].(float64); ok && dp > 0 {
				dstPort = uint32(dp)
			}
		}
	}

	event := DetectionEvent{
		IP:                 firstSignal.IP,
		DestIP:             destIP,
		DstPort:            dstPort,
		Hostname:           hostname,
		Method:             method,
		Path:               path,
		JA4H:               firstSignal.JA4H,
		JA4T:               firstSignal.JA4T,
		ASN:                firstSignal.ASN,
		Org:                firstSignal.Org,
		UserAgent:          userAgent,
		Signals:            signals,
		SignalCount:        len(signals),
		DetectionTime:      time.Now(),
		EWMABaseline:       ewmaBaseline,
		Confidence:         confidence, // ML confidence (or DDoS-boosted)
		Score:              score,
		MLConfidence:       mlConfidence,
		RuleConfidence:     ruleConfidence, // Rule-based confidence (display only)
		MLCategory:         mlCategory,
		MLModelTier:        mlModelTier, // Which ML tier made the prediction
		BotCategory:        botCategory,
		VerificationStatus: verified,
		BlockReason:        blockReason,
		WouldBlock:         wouldBlock,
		SignalBreakdown:    signalTypes,
		SourceBreakdown:    sources,
	}
	if ddosInfo != nil {
		if b, err := json.Marshal(ddosInfo); err == nil {
			event.Reasons = append(event.Reasons, "ddos:"+string(b))
		}
	}

	// Track ML tier usage
	if mlModelTier != "" {
		e.trackMLTier(mlModelTier)
	}

	// Start session recording for ML training ONLY if IP is in the learning window
	// This prevents recording too many sessions - only record IPs we've explicitly marked for learning
	if event.IP != nil && e.feedback != nil {
		if _, inLearning, _ := e.feedback.GetLearningLabel(event.IP.String()); inLearning {
			// Only record if confidence is significant (would block or >0.5)
			if wouldBlock || confidence > 0.5 {
				e.startSessionRecording(event.IP.String(), &event)
			}
		}
	}

	metrics.AIDetectionsTotal.Inc()
	metrics.AIDetectionConfidence.Observe(confidence)
	metrics.AIConfidenceByCategory.WithLabelValues(string(botCategory)).Observe(confidence)

	if event.IP != nil && metrics.IsHighCardinalityEnabled() {
		metrics.AIDetectionsByIP.WithLabelValues(event.IP.String()).Inc()
	}

	asnTag := event.ASN
	orgTag := event.Org
	if asnTag == "" {
		asnTag = "Unknown"
	}
	if orgTag == "" {
		orgTag = "Unknown"
	}
	metrics.AIDetectionsByASN.WithLabelValues(asnTag, orgTag).Inc()
	metrics.AISignalEWMAByASN.WithLabelValues(asnTag, orgTag).Set(ewmaBaseline)

	if event.JA4H != "" && metrics.IsHighCardinalityEnabled() {
		metrics.AIDetectionsByJA4H.WithLabelValues(event.JA4H).Inc()
		metrics.AISignalEWMAByJA4H.WithLabelValues(event.JA4H).Set(ewmaBaseline)
	}

	e.metricsMu.Lock()
	if event.IP != nil {
		e.detectionsByIP[event.IP.String()]++
	}
	if event.ASN != "" {
		e.detectionsByASN[event.ASN]++
	}
	if event.JA4H != "" {
		e.detectionsByJA4H[event.JA4H]++
	}
	e.metricsMu.Unlock()

	// Cache latest detection for UI display (skip allowlisted IPs)
	skipCache := false
	if e.feedback != nil && event.IP != nil {
		if e.feedback.IsAllowlisted(event.IP.String()) {
			skipCache = true
		}
	}

	if !skipCache {
		e.detectionsMu.Lock()
		if event.IP != nil {
			e.latestDetections["ip:"+event.IP.String()] = &event
		}
		if event.ASN != "" {
			e.latestDetections["asn:"+event.ASN] = &event
		}
		if event.JA4H != "" {
			e.latestDetections["ja4h:"+event.JA4H] = &event
		}
		e.detectionsMu.Unlock()

		// Add to history (make a copy)
		e.historyMu.Lock()
		eventCopy := event
		e.detectionHistory = append(e.detectionHistory, &eventCopy)

		// Trim history if too large
		if len(e.detectionHistory) > e.historyMaxSize {
			e.detectionHistory = e.detectionHistory[len(e.detectionHistory)-e.historyMaxSize:]
		}
		e.historyMu.Unlock()
	}

	// Track bot category metrics
	metrics.AIDetectionsByBotCategory.WithLabelValues(string(botCategory)).Inc()
	metrics.AIVerificationResults.WithLabelValues(string(verified)).Inc()
	if behavioralProfile != nil {
		if behavioralProfile.IsPersistent {
			metrics.AIBehavioralPatterns.WithLabelValues("persistent").Inc()
		}
		if behavioralProfile.IsHighFrequency {
			metrics.AIBehavioralPatterns.WithLabelValues("high_frequency").Inc()
		}
		if behavioralProfile.IsBursty {
			metrics.AIBehavioralPatterns.WithLabelValues("bursty").Inc()
		}
	}

	if e.reputation != nil {
		if event.IP != nil {
			e.reputation.Penalize(event.IP.String(), reputation.TypeIP, 10.0*confidence, "AI detection")
		}
		if event.ASN != "" && event.ASN != "Unknown" {
			// Mark abusive IP for ASN scaling
			e.markASNAbusive(event.ASN, event.Org, event.IP)
			scale := e.asnPenaltyScale(event.ASN)
			e.reputation.PenalizeASN(event.ASN, event.IP.String(), 2.0*confidence*scale, "AI detection")
		}
		if event.JA4H != "" {
			e.reputation.Penalize(event.JA4H, reputation.TypeJA4, 6.0*confidence, "AI detection")
		}
	}

	// Check if we're in warmup period
	inWarmup := time.Since(e.startupTime) < e.warmupPeriod

	// Build signal breakdown for logging
	signalBreakdown := make(map[string]interface{})
	for sigType, count := range event.SignalBreakdown {
		signalBreakdown[string(sigType)] = count
	}
	sourceBreakdown := make(map[string]interface{})
	for source, count := range event.SourceBreakdown {
		sourceBreakdown[string(source)] = count
	}

	logFields := logrus.Fields{
		"component":        "aidetection_engine",
		"event":            "ai_detection",
		"ip":               event.IP,
		"ja4h":             event.JA4H,
		"asn":              event.ASN,
		"signal_count":     event.SignalCount,
		"confidence":       confidence,
		"bot_category":     botCategory,
		"verification":     verified,
		"ewma_baseline":    ewmaBaseline,
		"signal_breakdown": signalBreakdown,
		"source_breakdown": sourceBreakdown,
		"ml_confidence":    mlConfidence,
		"ml_category":      mlCategory,
		"ml_is_bot":        mlConfidence > 0,
	}

	// Log throttle by entity key
	logKey := "unknown"
	if event.IP != nil {
		logKey = "ip:" + event.IP.String()
	} else if event.JA4H != "" {
		logKey = "ja4h:" + event.JA4H
	} else if event.ASN != "" {
		logKey = "asn:" + event.ASN
	}

	if inWarmup {
		warmupRemaining := e.warmupPeriod - time.Since(e.startupTime)
		logFields["warmup"] = true
		logFields["warmup_remaining"] = warmupRemaining.String()
		if e.shouldLogDetection(logKey) {
			logrus.WithFields(logFields).Debug("AI Detection Triggered (Warmup - Not Blocking)")
		}
		// Don't call handlers during warmup - no blocking
		return
	} else {
		if e.shouldLogDetection(logKey) {
			logrus.WithFields(logFields).Info("AI Detection Triggered")
		}
	}

	// Auto-train ML model if IP is in learning window
	if e.feedback != nil && event.IP != nil && e.mlModel != nil {
		if label, inWindow, trainCount := e.feedback.GetLearningLabel(event.IP.String()); inWindow {
			logrus.WithFields(logrus.Fields{
				"ip":          event.IP.String(),
				"label":       label,
				"train_count": trainCount,
				"in_window":   inWindow,
			}).Info("Auto-training: IP in learning window")

			// Accumulate behavioral data for pattern learning
			go func() {
				defer func() {
					if r := recover(); r != nil {
						logrus.WithField("panic", r).Error("Panic in behavioral data accumulation")
					}
				}()

				// Extract signal types from detection
				signalTypes := make([]string, 0, len(event.SignalBreakdown))
				for sigType := range event.SignalBreakdown {
					signalTypes = append(signalTypes, string(sigType))
				}

				// Accumulate data for comprehensive pattern learning
				e.feedback.AccumulateLearningData(event.IP.String(), LearningData{
					UserAgent:   event.UserAgent,
					JA4H:        event.JA4H,
					Path:        event.Path,
					SignalTypes: signalTypes,
				})

				logrus.WithFields(logrus.Fields{
					"ip":           event.IP.String(),
					"signal_types": len(signalTypes),
					"path":         event.Path,
				}).Debug("Accumulated behavioral data for learning")
			}()

			// Train the model with this detection
			go func() {
				defer func() {
					if r := recover(); r != nil {
						logrus.WithField("panic", r).Error("Panic in auto-training")
					}
				}()

				// Extract ML features
				mlFeatures := e.extractMLFeatures(
					event.Signals,
					event.SignalBreakdown,
					event.SourceBreakdown,
					nil, // profile not needed for training
					0,   // reputation not needed
				)

				// Train with the labeled data
				isMalicious := (label == "malicious")
				err := e.mlModel.Train(mlFeatures, isMalicious)

				if err == nil {
					e.feedback.IncrementLearningTrainCount(event.IP.String())
					logrus.WithFields(logrus.Fields{
						"ip":          event.IP.String(),
						"label":       label,
						"train_count": trainCount + 1,
						"confidence":  event.Confidence,
					}).Info("Auto-trained ML model from learning window")
				} else {
					logrus.WithError(err).Warn("Failed to auto-train ML model")
				}
			}()
		}
	}

	e.mu.RLock()
	handlers := e.detectionHandlers
	e.mu.RUnlock()

	for _, handler := range handlers {
		handler.HandleDetection(event)
	}
}

// GetMetrics returns current detection metrics
func (e *Engine) GetMetrics() (map[string]uint64, map[string]uint64, map[string]uint64, map[string]uint64, map[string]uint64, map[string]uint64) {
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()

	copyMap := func(src map[string]uint64) map[string]uint64 {
		dst := make(map[string]uint64, len(src))
		for k, v := range src {
			dst[k] = v
		}
		return dst
	}

	return copyMap(e.signalsByIP), copyMap(e.detectionsByIP), copyMap(e.signalsByASN), copyMap(e.detectionsByASN), copyMap(e.signalsByJA4H), copyMap(e.detectionsByJA4H)
}

// GetDetectionsByIP returns detection counts by IP
func (e *Engine) GetDetectionsByIP() map[string]int {
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()

	result := make(map[string]int, len(e.detectionsByIP))
	for k, v := range e.detectionsByIP {
		result[k] = int(v)
	}
	return result
}

// GetDetectionsByJA4H returns detection counts by JA4H
func (e *Engine) GetDetectionsByJA4H() map[string]int {
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()

	result := make(map[string]int, len(e.detectionsByJA4H))
	for k, v := range e.detectionsByJA4H {
		result[k] = int(v)
	}
	return result
}

// GetDetectionsByASN returns detection counts by ASN
func (e *Engine) GetDetectionsByASN() map[string]int {
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()

	result := make(map[string]int, len(e.detectionsByASN))
	for k, v := range e.detectionsByASN {
		result[k] = int(v)
	}
	return result
}

// GetEntitySignalBreakdown returns detailed signal breakdown for a specific entity
func (e *Engine) GetEntitySignalBreakdown(key string, entityType string) (map[string]uint64, map[string]uint64) {
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()

	byType := make(map[string]uint64)
	bySource := make(map[string]uint64)

	switch entityType {
	case "ip":
		if types, ok := e.signalTypesByIP[key]; ok {
			for k, v := range types {
				byType[k] = v
			}
		}
		if sources, ok := e.signalSourcesByIP[key]; ok {
			for k, v := range sources {
				bySource[k] = v
			}
		}
	case "asn":
		if types, ok := e.signalTypesByASN[key]; ok {
			for k, v := range types {
				byType[k] = v
			}
		}
		if sources, ok := e.signalSourcesByASN[key]; ok {
			for k, v := range sources {
				bySource[k] = v
			}
		}
	case "ja4h":
		if types, ok := e.signalTypesByJA4H[key]; ok {
			for k, v := range types {
				byType[k] = v
			}
		}
		if sources, ok := e.signalSourcesByJA4H[key]; ok {
			for k, v := range sources {
				bySource[k] = v
			}
		}
	}

	return byType, bySource
}

// updateBehavioralProfile updates or creates a behavioral profile for an entity
func (e *Engine) updateBehavioralProfile(entityID string, signal Signal, signalTypes map[SignalType]bool, sources map[SignalSource]bool) {
	e.profilesMu.Lock()
	defer e.profilesMu.Unlock()

	profile, exists := e.behavioralProfiles[entityID]
	if !exists {
		profile = &BehavioralProfile{
			EntityID:    entityID,
			FirstSeen:   signal.Timestamp,
			TimeWindows: make([]time.Time, 0, 100),
		}
		e.behavioralProfiles[entityID] = profile
	}

	// Update profile
	profile.LastSeen = signal.Timestamp
	profile.SignalCount++
	profile.TimeWindows = append(profile.TimeWindows, signal.Timestamp)

	// Keep only last 100 timestamps
	if len(profile.TimeWindows) > 100 {
		profile.TimeWindows = profile.TimeWindows[1:]
	}

	// Calculate signal rate (signals per minute)
	timeSpan := profile.LastSeen.Sub(profile.FirstSeen).Seconds()
	if timeSpan > 0 {
		profile.SignalRate = float64(profile.SignalCount) / (timeSpan / 60.0)
	}

	// Update diversity metrics
	profile.SignalDiversity = float64(len(signalTypes))
	profile.SourceDiversity = float64(len(sources))

	// Check persistence (activity > 1 hour)
	profile.IsPersistent = timeSpan > 3600

	// Check if high frequency (> 10 signals per minute)
	profile.IsHighFrequency = profile.SignalRate > 10.0

	// Check burstiness (high variance in timing)
	if len(profile.TimeWindows) >= 3 {
		profile.IsBursty = e.calculateBurstiness(profile.TimeWindows)
	}
}

// calculateBurstiness determines if request pattern is bursty
func (e *Engine) calculateBurstiness(timestamps []time.Time) bool {
	if len(timestamps) < 3 {
		return false
	}

	// Calculate intervals between requests
	intervals := make([]float64, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		intervals[i-1] = timestamps[i].Sub(timestamps[i-1]).Seconds()
	}

	// Calculate coefficient of variation (std dev / mean)
	var sum, sumSq float64
	for _, interval := range intervals {
		sum += interval
		sumSq += interval * interval
	}
	mean := sum / float64(len(intervals))
	variance := (sumSq / float64(len(intervals))) - (mean * mean)
	stdDev := math.Sqrt(variance)

	cv := stdDev / mean
	// CV > 1.0 indicates bursty behavior
	return cv > 1.0
}

// GetBehavioralProfile returns the behavioral profile for an entity
func (e *Engine) GetBehavioralProfile(entityID string) *BehavioralProfile {
	e.profilesMu.Lock()
	defer e.profilesMu.Unlock()

	if profile, ok := e.behavioralProfiles[entityID]; ok {
		// Return a copy to avoid race conditions
		profileCopy := *profile
		return &profileCopy
	}
	return nil
}

// GetLatestDetection returns the most recent detection event for an entity (IP, ASN, or JA4H)
func (e *Engine) GetLatestDetection(entityID string) *DetectionEvent {
	e.detectionsMu.Lock()
	defer e.detectionsMu.Unlock()

	if det, ok := e.latestDetections[entityID]; ok {
		// Return a copy to avoid race conditions
		detCopy := *det
		return &detCopy
	}
	return nil
}

// GetAllLatestDetections returns all cached detection events (excluding allowlisted IPs)
func (e *Engine) GetAllLatestDetections() []*DetectionEvent {
	e.detectionsMu.Lock()
	defer e.detectionsMu.Unlock()

	// Use a map to deduplicate by IP address (same detection stored under ip:, asn:, ja4h: keys)
	seen := make(map[string]bool)
	detections := make([]*DetectionEvent, 0, len(e.latestDetections))

	for _, det := range e.latestDetections {
		// Skip allowlisted IPs
		if e.feedback != nil && det.IP != nil {
			if e.feedback.IsAllowlisted(det.IP.String()) {
				continue
			}
		}

		// Deduplicate by IP
		if det.IP != nil {
			ipStr := det.IP.String()
			if seen[ipStr] {
				continue
			}
			seen[ipStr] = true
		}

		detCopy := *det
		detections = append(detections, &detCopy)
	}
	return detections
}

// GetVerifiedBots returns all verified legitimate bots (search engines, AI crawlers)
func (e *Engine) GetVerifiedBots() []*DetectionEvent {
	e.detectionsMu.Lock()
	defer e.detectionsMu.Unlock()

	seen := make(map[string]bool)
	verifiedBots := make([]*DetectionEvent, 0)

	for _, det := range e.latestDetections {
		// Only include verified legitimate bots
		if det.VerificationStatus != VerificationVerified || det.BotCategory != BotCategoryLegitimate {
			continue
		}

		// Deduplicate by IP
		if det.IP != nil {
			ipStr := det.IP.String()
			if seen[ipStr] {
				continue
			}
			seen[ipStr] = true
		}

		detCopy := *det
		verifiedBots = append(verifiedBots, &detCopy)
	}
	return verifiedBots
}

// GetDetectionHistory returns detection events from the last 6 hours (excluding allowlisted IPs)
func (e *Engine) GetDetectionHistory(maxAge time.Duration) []*DetectionEvent {
	e.historyMu.Lock()
	defer e.historyMu.Unlock()

	if maxAge == 0 {
		maxAge = e.historyMaxAge
	}

	cutoff := time.Now().Add(-maxAge)
	detections := make([]*DetectionEvent, 0, len(e.detectionHistory))

	// Use map to deduplicate by IP within time window
	seen := make(map[string]time.Time) // IP -> most recent detection time

	for _, det := range e.detectionHistory {
		// Skip old detections
		if det.DetectionTime.Before(cutoff) {
			continue
		}

		// Skip allowlisted IPs
		if e.feedback != nil && det.IP != nil {
			if e.feedback.IsAllowlisted(det.IP.String()) {
				continue
			}
		}

		// Deduplicate: keep only most recent detection per IP
		if det.IP != nil {
			ipStr := det.IP.String()
			if lastSeen, exists := seen[ipStr]; exists {
				if det.DetectionTime.Before(lastSeen) {
					continue // Skip older detection for this IP
				}
				// Remove old detection from result
				for i, d := range detections {
					if d.IP != nil && d.IP.String() == ipStr {
						detections = append(detections[:i], detections[i+1:]...)
						break
					}
				}
			}
			seen[ipStr] = det.DetectionTime
		}

		detCopy := *det
		detections = append(detections, &detCopy)
	}

	// Sort by detection time (newest first)
	for i := 0; i < len(detections)-1; i++ {
		for j := i + 1; j < len(detections); j++ {
			if detections[i].DetectionTime.Before(detections[j].DetectionTime) {
				detections[i], detections[j] = detections[j], detections[i]
			}
		}
	}

	return detections
}

// extractMLFeatures extracts ML features from signals for model prediction
func (e *Engine) extractMLFeatures(
	signals []Signal,
	signalTypes map[SignalType]int,
	sources map[SignalSource]int,
	profile *BehavioralProfile,
	reputationScore float64,
) MLFeatures {
	now := time.Now()

	// Basic features
	signalCount := len(signals)
	signalDiversity := len(signalTypes)
	sourceDiversity := len(sources)

	// Temporal features
	var timeSpan float64
	var isBursty bool
	if len(signals) > 1 {
		timeSpan = signals[len(signals)-1].Timestamp.Sub(signals[0].Timestamp).Seconds()
	}
	if profile != nil {
		isBursty = profile.IsBursty
	}

	timeOfDay := now.Hour()
	dayOfWeek := int(now.Weekday())

	// Signal rate (signals per minute)
	signalRate := 0.0
	if timeSpan > 0 {
		signalRate = float64(signalCount) / (timeSpan / 60.0)
	} else if signalCount > 0 {
		signalRate = float64(signalCount) // All in same second
	}

	// Network features (with safety check for empty signals array)
	hasASN := false
	hasJA4H := false
	geoCountry := ""
	var firstIP net.IP

	if len(signals) > 0 {
		hasASN = signals[0].ASN != ""
		hasJA4H = signals[0].JA4H != ""
		firstIP = signals[0].IP
		// GeoIP provider only returns ASN, not country
		// Country would require separate GeoIP2 country database
		if hasASN {
			geoCountry = signals[0].ASN // Use ASN as proxy for now
		}
	}

	// Behavioral features
	requestRate := 0.0
	detectionHistory := 0
	if profile != nil {
		requestRate = profile.RequestRate
		detectionHistory = int(profile.DetectionCount)
	}

	// Threat Intelligence features
	var threatScore float64
	var isKnownScanner, isCloud, isTor, isVPN, hasVulns bool
	var openPorts int
	var threatTags []string

	if e.threatIntel != nil && firstIP != nil {
		enrichedInfo := e.threatIntel.GetEnrichedInfo(firstIP)
		if enrichedInfo != nil {
			threatScore = enrichedInfo.ThreatScore
			isKnownScanner = enrichedInfo.IsKnownScanner
			isCloud = enrichedInfo.IsCloud
			isTor = enrichedInfo.IsTor
			isVPN = enrichedInfo.IsVPN
			hasVulns = enrichedInfo.Vulnerabilities > 0
			openPorts = enrichedInfo.OpenPorts
			threatTags = enrichedInfo.Tags
		}
	}

	// Build feature vector
	mlFeatures := MLFeatures{
		SignalCount:        signalCount,
		SignalRate:         signalRate,
		SignalDiversity:    signalDiversity,
		SourceDiversity:    sourceDiversity,
		TimeSpan:           timeSpan,
		IsBursty:           isBursty,
		TimeOfDay:          timeOfDay,
		DayOfWeek:          dayOfWeek,
		HasASN:             hasASN,
		HasJA4H:            hasJA4H,
		GeoCountry:         geoCountry,
		RequestRate:        requestRate,
		DetectionHistory:   detectionHistory,
		ReputationScore:    reputationScore,
		ThreatScore:        threatScore,
		IsKnownScanner:     isKnownScanner,
		IsCloud:            isCloud,
		IsTor:              isTor,
		IsVPN:              isVPN,
		HasVulnerabilities: hasVulns,
		OpenPortCount:      openPorts,
		ThreatTags:         threatTags,
		SignalTypeVector:   signalTypes,
		SourceVector:       sources,
	}

	// Add event history for advanced 100-feature model
	if e.historyManager != nil && len(signals) > 0 && signals[0].IP != nil {
		ipStr := signals[0].IP.String()
		if history, exists := e.historyManager.GetHistory(ipStr); exists {
			snapshot := history.GetSnapshot()
			mlFeatures.EventHistory = &snapshot
		}
	}

	return mlFeatures
}

// capturePreDetectionEvent adds signal to rolling buffer for an IP
func (e *Engine) capturePreDetectionEvent(ip string, signal Signal) {
	e.preDetectionBufferMu.Lock()
	defer e.preDetectionBufferMu.Unlock()

	// Initialize ring buffer if not exists (100 events)
	if e.preDetectionBuffers[ip] == nil {
		e.preDetectionBuffers[ip] = ring.New(100)
	}

	// Add signal to ring buffer
	e.preDetectionBuffers[ip].Value = signal
	e.preDetectionBuffers[ip] = e.preDetectionBuffers[ip].Next()
}

// getPreDetectionEvents extracts pre-detection signals from ring buffer
func (e *Engine) getPreDetectionEvents(ip string) []Signal {
	e.preDetectionBufferMu.Lock()
	defer e.preDetectionBufferMu.Unlock()

	r := e.preDetectionBuffers[ip]
	if r == nil {
		return []Signal{}
	}

	events := make([]Signal, 0, 100)
	r.Do(func(v interface{}) {
		if v != nil {
			if sig, ok := v.(Signal); ok {
				events = append(events, sig)
			}
		}
	})

	return events
}

// startSessionRecording begins recording all events for an IP after detection
func (e *Engine) startSessionRecording(ip string, detection *DetectionEvent) {
	e.sessionRecordingsMu.Lock()
	defer e.sessionRecordingsMu.Unlock()

	// Don't record if already recording
	if _, exists := e.sessionRecordings[ip]; exists {
		return
	}

	sessionID := ip + "_" + time.Now().Format("20060102_150405")

	recording := &SessionRecording{
		SessionID:  sessionID,
		IP:         ip,
		StartTime:  time.Now(),
		PreEvents:  e.getPreDetectionEvents(ip),
		PostEvents: make([]Signal, 0, 500),
		Detection:  detection,
		Outcome:    "recording",
	}

	e.sessionRecordings[ip] = recording

	logrus.WithFields(logrus.Fields{
		"session_id": sessionID,
		"ip":         ip,
		"pre_events": len(recording.PreEvents),
	}).Debug("Started session recording for ML training")

	// Stop recording after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		e.finalizeRecording(ip)
	}()
}

// StartRecordingForIP starts recording immediately for a labeled IP (called from feedback)
func (e *Engine) StartRecordingForIP(ip string, label string) {
	// Get the latest detection for this IP to use as context
	detection := e.GetLatestDetection("ip:" + ip)
	if detection == nil {
		// Create a minimal detection event for recording context
		ipAddr := net.ParseIP(ip)
		detection = &DetectionEvent{
			IP:            ipAddr,
			DetectionTime: time.Now(),
			BotCategory:   BotCategoryUnknown,
			Confidence:    0.0,
		}
	}

	e.startSessionRecording(ip, detection)

	// Store the label in the active recording
	e.sessionRecordingsMu.Lock()
	if recording := e.sessionRecordings[ip]; recording != nil {
		recording.Label = label
	}
	e.sessionRecordingsMu.Unlock()

	logrus.WithFields(logrus.Fields{
		"ip":    ip,
		"label": label,
	}).Info("Started immediate session recording for labeled IP")
}

// capturePostDetectionEvent adds event to active recording
// Caller must hold sessionRecordingsMu lock
func (e *Engine) capturePostDetectionEventLocked(ip string, signal Signal) {
	recording := e.sessionRecordings[ip]
	if recording != nil {
		recording.PostEvents = append(recording.PostEvents, signal)
	}
}

// capturePostDetectionEvent adds event to active recording (with lock)
func (e *Engine) capturePostDetectionEvent(ip string, signal Signal) {
	e.sessionRecordingsMu.Lock()
	defer e.sessionRecordingsMu.Unlock()
	e.capturePostDetectionEventLocked(ip, signal)
}

// finalizeRecording completes a session recording and moves to completed list
func (e *Engine) finalizeRecording(ip string) {
	e.sessionRecordingsMu.Lock()
	recording := e.sessionRecordings[ip]
	delete(e.sessionRecordings, ip)
	e.sessionRecordingsMu.Unlock()

	if recording == nil {
		return
	}

	recording.EndTime = time.Now()
	recording.Duration = recording.EndTime.Sub(recording.StartTime)
	recording.TotalEvents = len(recording.PreEvents) + len(recording.PostEvents)

	// Determine outcome based on post-detection behavior
	if len(recording.PostEvents) == 0 {
		recording.Outcome = "disappeared"
	} else if len(recording.PostEvents) > 50 {
		recording.Outcome = "escalated"
	} else if recording.Detection != nil && recording.Detection.WouldBlock {
		recording.Outcome = "blocked"
	} else {
		recording.Outcome = "allowed"
	}

	// Write to disk immediately (don't keep in memory)
	if err := e.persistSessionRecording(recording); err != nil {
		logrus.WithError(err).WithField("session_id", recording.SessionID).Error("Failed to persist session recording")
		// Fallback: add to in-memory buffer
		e.completedRecordingsMu.Lock()
		e.completedRecordings = append(e.completedRecordings, recording)
		if len(e.completedRecordings) > e.maxCompletedRecordings {
			e.completedRecordings = e.completedRecordings[1:]
		}
		e.completedRecordingsMu.Unlock()
	} else {
		logrus.WithFields(logrus.Fields{
			"session_id":   recording.SessionID,
			"ip":           ip,
			"duration":     recording.Duration,
			"total_events": recording.TotalEvents,
			"outcome":      recording.Outcome,
		}).Info("Persisted session recording to disk for ML training")
	}
}

// GetCompletedRecordings returns all completed session recordings
func (e *Engine) GetCompletedRecordings() []*SessionRecording {
	e.completedRecordingsMu.Lock()
	defer e.completedRecordingsMu.Unlock()

	// Return copy
	recordings := make([]*SessionRecording, len(e.completedRecordings))
	copy(recordings, e.completedRecordings)
	return recordings
}

// ClearCompletedRecordings removes all completed recordings (after export)
func (e *Engine) ClearCompletedRecordings() {
	e.completedRecordingsMu.Lock()
	defer e.completedRecordingsMu.Unlock()

	e.completedRecordings = make([]*SessionRecording, 0, 1000)
	logrus.Info("Cleared completed session recordings")
}

// persistSessionRecording writes a session recording to disk as JSONL
func (e *Engine) persistSessionRecording(recording *SessionRecording) error {
	if e.sessionRecordingsPath == "" {
		e.sessionRecordingsPath = "/var/cache/packetyeeter/sessions"
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(e.sessionRecordingsPath, 0755); err != nil {
		return fmt.Errorf("failed to create session recordings directory: %w", err)
	}

	// Sanitize IP for filename (replace : with - for IPv6)
	sanitizedIP := strings.ReplaceAll(recording.IP, ":", "-")

	// Use IP and timestamp based filename for easy identification
	timestamp := recording.StartTime.Format("2006-01-02T15-04-05")
	filename := filepath.Join(e.sessionRecordingsPath, fmt.Sprintf("recording-%s-%s.jsonl", sanitizedIP, timestamp))

	// Open file in append mode
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open session recording file: %w", err)
	}
	defer f.Close()

	// Serialize recording as JSON
	data, err := json.Marshal(recording)
	if err != nil {
		return fmt.Errorf("failed to marshal session recording: %w", err)
	}

	// Write as JSONL (one line per recording)
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write session recording: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"file":        filename,
		"session_id":  recording.SessionID,
		"data_length": len(data),
	}).Info("✅ Session recording file written successfully")

	return nil
}

// GetActiveRecordings returns information about currently active recordings
func (e *Engine) GetActiveRecordings() []ActiveRecordingInfo {
	e.sessionRecordingsMu.Lock()
	defer e.sessionRecordingsMu.Unlock()

	var recordings []ActiveRecordingInfo
	for ip, recording := range e.sessionRecordings {
		elapsed := time.Since(recording.StartTime)
		remaining := 5*time.Minute - elapsed // 5 minute default recording duration
		if remaining < 0 {
			remaining = 0
		}

		initialCategory := "unknown"
		if recording.Detection != nil {
			initialCategory = string(recording.Detection.BotCategory)
		}

		// Calculate current event count (TotalEvents is only set on finalize)
		currentEventCount := len(recording.PreEvents) + len(recording.PostEvents)

		recordings = append(recordings, ActiveRecordingInfo{
			IP:              ip,
			StartTime:       recording.StartTime,
			Elapsed:         elapsed,
			Remaining:       remaining,
			EventCount:      currentEventCount,
			SessionID:       recording.SessionID,
			InitialCategory: initialCategory,
			Label:           recording.Label,
		})
	}

	return recordings
}

// ClearLearningWindow removes all learning labels
func (e *Engine) ClearLearningWindow() int {
	if e.feedback == nil {
		return 0
	}
	return e.feedback.ClearLearningWindow()
}

// BulkRemoveFromLearningWindow removes multiple IPs from learning window
func (e *Engine) BulkRemoveFromLearningWindow(ips []string) int {
	if e.feedback == nil {
		return 0
	}
	return e.feedback.BulkRemoveFromLearningWindow(ips)
}

// GetLearningWindowIPs returns all IPs currently in the learning window
func (e *Engine) GetLearningWindowIPs() []string {
	if e.feedback == nil {
		return []string{}
	}
	return e.feedback.GetLearningWindowIPs()
}
