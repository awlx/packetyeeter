package aidetection

import (
	"encoding/json"
	"math"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// OutcomeType represents the outcome of a detection
type OutcomeType string

const (
	OutcomeTruePositive  OutcomeType = "true_positive"  // Correctly identified bot/attack
	OutcomeFalsePositive OutcomeType = "false_positive" // Incorrectly flagged legitimate user
	OutcomeUnknown       OutcomeType = "unknown"        // Outcome not yet determined
)

// DetectionOutcome records the result of a detection decision
type DetectionOutcome struct {
	IP           string
	ASN          string
	Timestamp    time.Time
	Outcome      OutcomeType
	Confidence   float64
	Threshold    float64
	BotCategory  BotCategory
	SignalCount  int
	WasBlocked   bool
	ReportedByIP string // If user reported false positive
}

// FeedbackLoop tracks detection outcomes and adaptively adjusts thresholds
// to minimize false positives while maintaining detection effectiveness.
type FeedbackLoop struct {
	mu sync.RWMutex

	// Outcome tracking
	outcomes     []DetectionOutcome // Recent outcomes (rolling window)
	maxOutcomes  int                // Max outcomes to keep
	windowPeriod time.Duration      // Time window for FP rate calculation

	// Per-entity tracking
	falsePositiveIPs  map[string]time.Time // IP -> last FP time
	truePositiveIPs   map[string]int       // IP -> TP count
	falsePositiveASNs map[string]int       // ASN -> FP count in window
	truePositiveASNs  map[string]int       // ASN -> TP count in window

	// Adaptive threshold
	currentThreshold   float64 // Current detection threshold
	minThreshold       float64 // Minimum threshold (don't go below)
	maxThreshold       float64 // Maximum threshold (don't exceed)
	targetFPRate       float64 // Target false positive rate (e.g., 0.01 = 1%)
	adjustmentStep     float64 // How much to adjust threshold per adjustment
	lastAdjustment     time.Time
	adjustmentInterval time.Duration // Minimum time between adjustments
	adjustmentCount    int           // Total adjustments made
	thresholdIncreases int           // How many times threshold was raised
	thresholdDecreases int           // How many times threshold was lowered

	// Statistics
	totalDetections   int
	totalBlocks       int
	totalFalsePos     int
	totalTruePos      int
	totalUnknown      int
	falsePositiveRate float64 // Current FP rate

	// Allowlist for verified false positives
	allowlist       map[string]time.Time // IP -> expiry time
	allowlistTTL    time.Duration
	persistencePath string // Path to save allowlist state

	// Active learning window for reinforcement
	learningIPs    map[string]LearningLabel // IP -> learning label and expiry
	learningWindow time.Duration            // How long to track IPs for learning (default: 10 minutes)

	// Pattern-based learning (never expires unless manually removed)
	learnedPatterns    map[string]LearnedPattern // pattern_key -> pattern with metadata
	patternsTTL        time.Duration             // Default: never expire (0 = infinite)
	patternsPath       string                    // Path to save learned patterns
	patternMaxObserved int                       // Max observations to keep per pattern (default: 1000)
}

// LearningLabel tracks IPs that should be used for ML training
// Accumulates behavioral data over the learning window to build comprehensive patterns
type LearningLabel struct {
	Label      string    // "legitimate" or "malicious"
	ExpiresAt  time.Time // When to stop auto-training from this IP
	LabeledAt  time.Time // When the label was applied
	TrainCount int       // How many times we've trained from this IP

	// Accumulated behavioral data over learning window
	UserAgent         string          // User agent observed
	ASN               string          // ASN observed
	JA4H              string          // JA4H fingerprint
	UniquePaths       map[string]bool // All unique paths accessed
	RequestCount      int             // Total requests observed
	SignalTypes       map[string]int  // Signal types seen
	TCPSignals        int             // TCP-specific signals (SYN flood, port scan)
	UDPSignals        int             // UDP-specific signals (floods)
	PathCrawlDetected bool            // Sequential path crawling pattern
}

// LearnedPattern represents a learned traffic pattern (user-agent, ASN, JA4H combo + behavioral signatures)
// These patterns are remembered indefinitely once learned, building up knowledge base
type LearnedPattern struct {
	Key                string    `json:"key"`                  // Unique key for pattern (e.g., "ua:Mozilla/5.0|asn:AS12345")
	UserAgent          string    `json:"user_agent"`           // User agent string (if part of pattern)
	ASN                string    `json:"asn"`                  // ASN (if part of pattern)
	JA4H               string    `json:"ja4h"`                 // JA4H fingerprint (if part of pattern)
	Label              string    `json:"label"`                // "legitimate" or "malicious"
	Confidence         float64   `json:"confidence"`           // Confidence in this pattern (0.0-1.0)
	ObservedCount      int       `json:"observed_count"`       // How many times we've seen this pattern
	LastSeen           time.Time `json:"last_seen"`            // Last time this pattern was observed
	FirstSeen          time.Time `json:"first_seen"`           // First time this pattern was labeled
	LabeledByUser      bool      `json:"labeled_by_user"`      // Was this manually labeled vs auto-learned?
	TruePositiveCount  int       `json:"true_positive_count"`  // How many confirmed correct classifications
	FalsePositiveCount int       `json:"false_positive_count"` // How many confirmed mistakes
	Notes              string    `json:"notes"`                // Optional notes from user

	// Behavioral signatures (for crawler/scraper detection)
	AvgPathDiversity   float64  `json:"avg_path_diversity"`   // Average unique paths per session
	AvgRequestRate     float64  `json:"avg_request_rate"`     // Average requests per second
	HasPathPattern     bool     `json:"has_path_pattern"`     // Sequential path crawling detected
	HasTCPPattern      bool     `json:"has_tcp_pattern"`      // TCP-specific behavior (port scanning, SYN floods)
	HasUDPPattern      bool     `json:"has_udp_pattern"`      // UDP-specific behavior (floods, amplification)
	TypicalSignalTypes []string `json:"typical_signal_types"` // Common signal types for this pattern
}

// FeedbackConfig holds configuration for the feedback loop
type FeedbackConfig struct {
	MaxOutcomes        int           // Max outcomes to track (default: 10000)
	WindowPeriod       time.Duration // Rolling window for FP rate (default: 1 hour)
	MinThreshold       float64       // Minimum threshold (default: 0.5)
	MaxThreshold       float64       // Maximum threshold (default: 0.85)
	InitialThreshold   float64       // Starting threshold (default: 0.65)
	TargetFPRate       float64       // Target FP rate (default: 0.01 = 1%)
	AdjustmentStep     float64       // Threshold adjustment step (default: 0.02)
	AdjustmentInterval time.Duration // Min time between adjustments (default: 5 minutes)
	AllowlistTTL       time.Duration // How long to allowlist FP IPs (default: 24 hours)
	PersistencePath    string        // Path to save allowlist state (default: /var/lib/packetyeeter/allowlist.json)
	PatternsTTL        time.Duration // How long to remember patterns (default: 0 = never expire)
	PatternsPath       string        // Path to save learned patterns (default: /var/lib/packetyeeter/learned_patterns.json)
	PatternMaxObserved int           // Max observations per pattern (default: 1000)
}

// DefaultFeedbackConfig returns sensible defaults
func DefaultFeedbackConfig() FeedbackConfig {
	return FeedbackConfig{
		MaxOutcomes:        10000,
		WindowPeriod:       1 * time.Hour,
		MinThreshold:       0.5,
		MaxThreshold:       0.85,
		InitialThreshold:   0.65,
		TargetFPRate:       0.01, // 1% false positive rate
		AdjustmentStep:     0.02,
		AdjustmentInterval: 5 * time.Minute,
		AllowlistTTL:       24 * time.Hour,
		PersistencePath:    "/var/lib/packetyeeter/allowlist.json",
		PatternsTTL:        0, // Never expire by default
		PatternsPath:       "/var/lib/packetyeeter/learned_patterns.json",
		PatternMaxObserved: 1000,
	}
}

// NewFeedbackLoop creates a new feedback loop
func NewFeedbackLoop(cfg FeedbackConfig) *FeedbackLoop {
	if cfg.MaxOutcomes == 0 {
		cfg = DefaultFeedbackConfig()
	}

	f := &FeedbackLoop{
		outcomes:           make([]DetectionOutcome, 0, cfg.MaxOutcomes),
		maxOutcomes:        cfg.MaxOutcomes,
		windowPeriod:       cfg.WindowPeriod,
		falsePositiveIPs:   make(map[string]time.Time),
		truePositiveIPs:    make(map[string]int),
		falsePositiveASNs:  make(map[string]int),
		truePositiveASNs:   make(map[string]int),
		currentThreshold:   cfg.InitialThreshold,
		minThreshold:       cfg.MinThreshold,
		maxThreshold:       cfg.MaxThreshold,
		targetFPRate:       cfg.TargetFPRate,
		adjustmentStep:     cfg.AdjustmentStep,
		adjustmentInterval: cfg.AdjustmentInterval,
		allowlist:          make(map[string]time.Time),
		allowlistTTL:       cfg.AllowlistTTL,
		persistencePath:    cfg.PersistencePath,
		learningIPs:        make(map[string]LearningLabel),
		learningWindow:     10 * time.Minute,
		learnedPatterns:    make(map[string]LearnedPattern),
		patternsTTL:        cfg.PatternsTTL,
		patternsPath:       cfg.PatternsPath,
		patternMaxObserved: cfg.PatternMaxObserved,
		lastAdjustment:     time.Now(),
	}

	// Load persisted allowlist
	f.loadAllowlist()

	// Load learned patterns
	f.loadPatterns()

	return f
}

// RecordOutcome records a detection outcome
func (f *FeedbackLoop) RecordOutcome(outcome DetectionOutcome) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if outcome.Timestamp.IsZero() {
		outcome.Timestamp = time.Now()
	}

	// Add to outcomes history
	f.outcomes = append(f.outcomes, outcome)
	if len(f.outcomes) > f.maxOutcomes {
		// Remove oldest
		f.outcomes = f.outcomes[1:]
	}

	// Update statistics
	f.totalDetections++
	if outcome.WasBlocked {
		f.totalBlocks++
	}

	switch outcome.Outcome {
	case OutcomeFalsePositive:
		f.totalFalsePos++
		f.falsePositiveIPs[outcome.IP] = outcome.Timestamp
		if outcome.ASN != "" && outcome.ASN != "Unknown" {
			f.falsePositiveASNs[outcome.ASN]++
		}

		// Add to temporary allowlist
		f.allowlist[outcome.IP] = time.Now().Add(f.allowlistTTL)

		// Add to learning window for reinforcement training
		f.learningIPs[outcome.IP] = LearningLabel{
			Label:             "legitimate",
			ExpiresAt:         time.Now().Add(f.learningWindow),
			LabeledAt:         time.Now(),
			TrainCount:        0,
			UniquePaths:       make(map[string]bool),
			SignalTypes:       make(map[string]int),
			UserAgent:         "",
			ASN:               outcome.ASN,
			JA4H:              "",
			RequestCount:      0,
			TCPSignals:        0,
			UDPSignals:        0,
			PathCrawlDetected: false,
		}

		logrus.WithFields(logrus.Fields{
			"ip":            outcome.IP,
			"asn":           outcome.ASN,
			"confidence":    outcome.Confidence,
			"threshold":     outcome.Threshold,
			"bot_category":  outcome.BotCategory,
			"was_blocked":   outcome.WasBlocked,
			"learning_mins": f.learningWindow.Minutes(),
		}).Warn("False positive recorded - added to allowlist and learning window")

		// Persist allowlist to disk
		go f.saveAllowlist()

	case OutcomeTruePositive:
		f.totalTruePos++
		f.truePositiveIPs[outcome.IP]++
		if outcome.ASN != "" && outcome.ASN != "Unknown" {
			f.truePositiveASNs[outcome.ASN]++
		}

		// Add to learning window for reinforcement training
		f.learningIPs[outcome.IP] = LearningLabel{
			Label:             "malicious",
			ExpiresAt:         time.Now().Add(f.learningWindow),
			LabeledAt:         time.Now(),
			TrainCount:        0,
			UniquePaths:       make(map[string]bool),
			SignalTypes:       make(map[string]int),
			UserAgent:         "",
			ASN:               outcome.ASN,
			JA4H:              "",
			RequestCount:      0,
			TCPSignals:        0,
			UDPSignals:        0,
			PathCrawlDetected: false,
		}

		logrus.WithFields(logrus.Fields{
			"ip":            outcome.IP,
			"asn":           outcome.ASN,
			"confidence":    outcome.Confidence,
			"learning_mins": f.learningWindow.Minutes(),
		}).Info("True positive reinforced - added to learning window")

	case OutcomeUnknown:
		f.totalUnknown++
	}

	// Recalculate FP rate
	f.calculateFPRate()

	// Consider threshold adjustment
	f.considerThresholdAdjustment()
}

// RecordFalsePositive is a convenience method for recording false positives
func (f *FeedbackLoop) RecordFalsePositive(ip, asn string, confidence float64, category BotCategory, wasBlocked bool) {
	f.RecordOutcome(DetectionOutcome{
		IP:          ip,
		ASN:         asn,
		Timestamp:   time.Now(),
		Outcome:     OutcomeFalsePositive,
		Confidence:  confidence,
		Threshold:   f.GetCurrentThreshold(),
		BotCategory: category,
		WasBlocked:  wasBlocked,
	})
}

// RecordTruePositive is a convenience method for recording true positives
func (f *FeedbackLoop) RecordTruePositive(ip, asn string, confidence float64, category BotCategory, wasBlocked bool) {
	f.RecordOutcome(DetectionOutcome{
		IP:          ip,
		ASN:         asn,
		Timestamp:   time.Now(),
		Outcome:     OutcomeTruePositive,
		Confidence:  confidence,
		Threshold:   f.GetCurrentThreshold(),
		BotCategory: category,
		WasBlocked:  wasBlocked,
	})
}

// IsAllowlisted checks if an IP is temporarily allowlisted due to false positive
func (f *FeedbackLoop) IsAllowlisted(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if expiry, exists := f.allowlist[ip]; exists {
		if time.Now().Before(expiry) {
			return true
		}
		// Expired, will be cleaned up later
	}
	return false
}

// GetLearningLabel checks if an IP is in the learning window and returns its label
// Returns (label, inWindow, trainCount) where label is "legitimate" or "malicious"
func (f *FeedbackLoop) GetLearningLabel(ip string) (string, bool, int) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if learning, exists := f.learningIPs[ip]; exists {
		if time.Now().Before(learning.ExpiresAt) {
			return learning.Label, true, learning.TrainCount
		}
		// Expired, will be cleaned up later
	}
	return "", false, 0
}

// IncrementLearningTrainCount increments the training count for an IP in the learning window
func (f *FeedbackLoop) IncrementLearningTrainCount(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if learning, exists := f.learningIPs[ip]; exists && time.Now().Before(learning.ExpiresAt) {
		learning.TrainCount++
		f.learningIPs[ip] = learning
	}
}

// AccumulateLearningData adds behavioral data to an IP in the learning window
// This is called on each detection to build up a comprehensive behavioral profile
func (f *FeedbackLoop) AccumulateLearningData(ip string, data LearningData) {
	f.mu.Lock()
	defer f.mu.Unlock()

	learning, exists := f.learningIPs[ip]
	if !exists || time.Now().After(learning.ExpiresAt) {
		return
	}

	// Accumulate data
	if data.UserAgent != "" && learning.UserAgent == "" {
		learning.UserAgent = data.UserAgent
	}
	if data.JA4H != "" && learning.JA4H == "" {
		learning.JA4H = data.JA4H
	}

	// Add unique paths
	if data.Path != "" {
		learning.UniquePaths[data.Path] = true
	}

	// Increment counters
	learning.RequestCount++

	// Track signal types
	for _, sigType := range data.SignalTypes {
		learning.SignalTypes[sigType]++

		// Check for TCP/UDP specific signals
		tcpSignals := map[string]bool{
			"syn_flood": true, "port_scanning": true, "incomplete_handshake": true,
			"tcp_metadata": true, "bad_flags": true,
		}
		udpSignals := map[string]bool{
			"udp_flood": true, "icmp_flood": true, "dns_amplification": true,
		}

		if tcpSignals[sigType] {
			learning.TCPSignals++
		}
		if udpSignals[sigType] {
			learning.UDPSignals++
		}
	}

	// Detect path crawling pattern (sequential or alphabetical paths)
	if len(learning.UniquePaths) >= 5 {
		learning.PathCrawlDetected = detectPathCrawlPattern(learning.UniquePaths)
	}

	f.learningIPs[ip] = learning
}

// LearningData contains behavioral information to accumulate
type LearningData struct {
	UserAgent   string
	JA4H        string
	Path        string
	SignalTypes []string
}

// detectPathCrawlPattern checks if paths show crawler/scraper behavior
func detectPathCrawlPattern(paths map[string]bool) bool {
	if len(paths) < 5 {
		return false
	}

	// Look for patterns like /1, /2, /3 or /page/1, /page/2
	// Or /a, /b, /c, or /api/users, /api/posts, /api/comments
	pathList := make([]string, 0, len(paths))
	for p := range paths {
		pathList = append(pathList, p)
	}

	// Simple heuristic: many unique paths = likely scraping
	// More sophisticated: check for sequential patterns
	return len(paths) > 10
}

// FinalizeLearningPattern is called when the learning window expires
// It creates a comprehensive pattern from accumulated behavioral data
func (f *FeedbackLoop) FinalizeLearningPattern(ip string) {
	f.mu.Lock()
	learning, exists := f.learningIPs[ip]
	f.mu.Unlock()

	if !exists {
		return
	}

	// Calculate behavioral metrics
	windowDuration := time.Since(learning.LabeledAt).Seconds()
	avgRequestRate := float64(learning.RequestCount) / windowDuration
	pathDiversity := float64(len(learning.UniquePaths))

	// Build typical signal types list
	typicalSignals := make([]string, 0, len(learning.SignalTypes))
	for sigType, count := range learning.SignalTypes {
		if count >= 2 { // Seen at least twice
			typicalSignals = append(typicalSignals, sigType)
		}
	}

	// Create pattern with behavioral signatures
	hasTCP := learning.TCPSignals >= 5
	hasUDP := learning.UDPSignals >= 3

	f.LearnPatternWithBehavior(
		learning.UserAgent,
		learning.ASN,
		learning.JA4H,
		learning.Label,
		false, // auto-learned
		"Auto-learned from 10-minute learning window",
		pathDiversity,
		avgRequestRate,
		learning.PathCrawlDetected,
		hasTCP,
		hasUDP,
		typicalSignals,
	)

	logrus.WithFields(logrus.Fields{
		"ip":             ip,
		"label":          learning.Label,
		"path_diversity": pathDiversity,
		"request_rate":   avgRequestRate,
		"path_crawl":     learning.PathCrawlDetected,
		"tcp_pattern":    hasTCP,
		"udp_pattern":    hasUDP,
		"signal_types":   len(typicalSignals),
	}).Info("Finalized learning pattern with behavioral signatures")
}

// GetCurrentThreshold returns the current adaptive threshold
func (f *FeedbackLoop) GetCurrentThreshold() float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.currentThreshold
}

// GetFalsePositiveRate returns the current false positive rate
func (f *FeedbackLoop) GetFalsePositiveRate() float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.falsePositiveRate
}

// calculateFPRate calculates the false positive rate over the rolling window
func (f *FeedbackLoop) calculateFPRate() {
	now := time.Now()
	cutoff := now.Add(-f.windowPeriod)

	// Count outcomes in window
	var totalInWindow, fpInWindow int
	for i := len(f.outcomes) - 1; i >= 0; i-- {
		outcome := f.outcomes[i]
		if outcome.Timestamp.Before(cutoff) {
			break // Outcomes are ordered by time
		}

		totalInWindow++
		if outcome.Outcome == OutcomeFalsePositive {
			fpInWindow++
		}
	}

	if totalInWindow > 0 {
		f.falsePositiveRate = float64(fpInWindow) / float64(totalInWindow)
	} else {
		f.falsePositiveRate = 0.0
	}
}

// considerThresholdAdjustment evaluates if threshold should be adjusted
func (f *FeedbackLoop) considerThresholdAdjustment() {
	now := time.Now()

	// Don't adjust too frequently
	if now.Sub(f.lastAdjustment) < f.adjustmentInterval {
		return
	}

	// Need enough data points
	if f.totalDetections < 100 {
		return
	}

	oldThreshold := f.currentThreshold
	adjusted := false

	// If FP rate too high, raise threshold (be more conservative)
	if f.falsePositiveRate > f.targetFPRate*1.5 { // 50% over target
		if f.currentThreshold < f.maxThreshold {
			f.currentThreshold += f.adjustmentStep
			if f.currentThreshold > f.maxThreshold {
				f.currentThreshold = f.maxThreshold
			}
			f.thresholdIncreases++
			adjusted = true

			logrus.WithFields(logrus.Fields{
				"old_threshold": oldThreshold,
				"new_threshold": f.currentThreshold,
				"fp_rate":       f.falsePositiveRate,
				"target_rate":   f.targetFPRate,
				"reason":        "fp_rate_too_high",
			}).Info("Feedback loop: increased detection threshold")
		}
	} else if f.falsePositiveRate < f.targetFPRate*0.5 { // 50% under target
		// FP rate very low, can afford to lower threshold (be more aggressive)
		// But only if we have enough true positives to justify it
		if f.totalTruePos > f.totalFalsePos*5 && f.currentThreshold > f.minThreshold {
			f.currentThreshold -= f.adjustmentStep
			if f.currentThreshold < f.minThreshold {
				f.currentThreshold = f.minThreshold
			}
			f.thresholdDecreases++
			adjusted = true

			logrus.WithFields(logrus.Fields{
				"old_threshold": oldThreshold,
				"new_threshold": f.currentThreshold,
				"fp_rate":       f.falsePositiveRate,
				"target_rate":   f.targetFPRate,
				"reason":        "fp_rate_very_low",
			}).Info("Feedback loop: decreased detection threshold")
		}
	}

	if adjusted {
		f.lastAdjustment = now
		f.adjustmentCount++
	}
}

// GetStatistics returns current statistics
func (f *FeedbackLoop) GetStatistics() map[string]interface{} {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Calculate learning stats
	learningLegitimate := 0
	learningMalicious := 0
	totalTrainCount := 0
	for _, learning := range f.learningIPs {
		if learning.Label == "legitimate" {
			learningLegitimate++
		} else if learning.Label == "malicious" {
			learningMalicious++
		}
		totalTrainCount += learning.TrainCount
	}

	// Count pattern types
	patternLegitimate := 0
	patternMalicious := 0
	for _, pattern := range f.learnedPatterns {
		if pattern.Label == "legitimate" {
			patternLegitimate++
		} else if pattern.Label == "malicious" {
			patternMalicious++
		}
	}

	return map[string]interface{}{
		"total_detections":     f.totalDetections,
		"total_blocks":         f.totalBlocks,
		"total_false_positive": f.totalFalsePos,
		"total_true_positive":  f.totalTruePos,
		"total_unknown":        f.totalUnknown,
		"false_positive_rate":  f.falsePositiveRate,
		"current_threshold":    f.currentThreshold,
		"target_fp_rate":       f.targetFPRate,
		"threshold_increases":  f.thresholdIncreases,
		"threshold_decreases":  f.thresholdDecreases,
		"adjustment_count":     f.adjustmentCount,
		"allowlist_size":       len(f.allowlist),
		"learned_patterns":     len(f.learnedPatterns),
		"patterns_legitimate":  patternLegitimate,
		"patterns_malicious":   patternMalicious,
		"fp_ips":               len(f.falsePositiveIPs),
		"tp_ips":               len(f.truePositiveIPs),
		"learning_window_size": len(f.learningIPs),
		"learning_legitimate":  learningLegitimate,
		"learning_malicious":   learningMalicious,
		"auto_train_count":     totalTrainCount,
	}
}

// Cleanup removes expired entries from tracking maps
func (f *FeedbackLoop) Cleanup() {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-f.windowPeriod)

	// Clean old outcomes
	i := 0
	for ; i < len(f.outcomes); i++ {
		if f.outcomes[i].Timestamp.After(cutoff) {
			break
		}
	}
	if i > 0 {
		f.outcomes = f.outcomes[i:]
	}

	// Clean expired allowlist entries
	for ip, expiry := range f.allowlist {
		if now.After(expiry) {
			delete(f.allowlist, ip)
		}
	}

	// Clean expired learning window entries and finalize patterns
	expiredLearningIPs := make([]string, 0)
	for ip, learning := range f.learningIPs {
		if now.After(learning.ExpiresAt) {
			expiredLearningIPs = append(expiredLearningIPs, ip)
		}
	}

	// Unlock mutex before finalizing patterns (which will re-lock)
	f.mu.Unlock()

	// Finalize patterns for expired learning windows
	for _, ip := range expiredLearningIPs {
		f.FinalizeLearningPattern(ip)
	}

	// Re-lock to clean up the map
	f.mu.Lock()
	for _, ip := range expiredLearningIPs {
		delete(f.learningIPs, ip)
	}

	// Clean old FP IPs (older than window period)
	for ip, ts := range f.falsePositiveIPs {
		if ts.Before(cutoff) {
			delete(f.falsePositiveIPs, ip)
		}
	}

	logrus.WithFields(logrus.Fields{
		"outcomes_kept":  len(f.outcomes),
		"allowlist_size": len(f.allowlist),
		"learning_size":  len(f.learningIPs),
		"fp_ips":         len(f.falsePositiveIPs),
	}).Debug("Feedback loop cleanup completed")

	// Save allowlist after cleanup
	go f.saveAllowlist()
}

// StartCleanup runs periodic cleanup
func (f *FeedbackLoop) StartCleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	go func() {
		for range ticker.C {
			f.Cleanup()
		}
	}()
}

// AllowlistEntry represents an IP in the allowlist
type AllowlistEntry struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetAllowlist returns all IPs currently in the allowlist
func (f *FeedbackLoop) GetAllowlist() []AllowlistEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()

	entries := make([]AllowlistEntry, 0, len(f.allowlist))
	for ip, expiry := range f.allowlist {
		entries = append(entries, AllowlistEntry{
			IP:        ip,
			ExpiresAt: expiry,
		})
	}
	return entries
}

// RemoveFromAllowlist removes an IP from the allowlist
func (f *FeedbackLoop) RemoveFromAllowlist(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.allowlist, ip)
	f.saveAllowlist()
	logrus.WithField("ip", ip).Info("Removed IP from allowlist")
}

// loadAllowlist loads the allowlist from disk
func (f *FeedbackLoop) loadAllowlist() {
	if f.persistencePath == "" {
		return
	}

	data, err := os.ReadFile(f.persistencePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logrus.WithError(err).Warn("Failed to load allowlist from disk")
		}
		return
	}

	var entries []AllowlistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		logrus.WithError(err).Error("Failed to parse allowlist file")
		return
	}

	now := time.Now()
	loaded := 0
	for _, entry := range entries {
		// Only load entries that haven't expired
		if entry.ExpiresAt.After(now) {
			f.allowlist[entry.IP] = entry.ExpiresAt
			loaded++
		}
	}

	if loaded > 0 {
		logrus.WithFields(logrus.Fields{
			"loaded": loaded,
			"total":  len(entries),
		}).Info("Loaded allowlist from disk")
	}
}

// saveAllowlist saves the allowlist to disk
func (f *FeedbackLoop) saveAllowlist() {
	if f.persistencePath == "" {
		return
	}

	entries := f.GetAllowlist()
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal allowlist")
		return
	}

	// Create directory if it doesn't exist
	dir := "/var/lib/packetyeeter"
	if err := os.MkdirAll(dir, 0755); err != nil {
		logrus.WithError(err).Warn("Failed to create persistence directory")
		return
	}

	if err := os.WriteFile(f.persistencePath, data, 0644); err != nil {
		logrus.WithError(err).Error("Failed to save allowlist to disk")
		return
	}

	logrus.WithField("entries", len(entries)).Debug("Saved allowlist to disk")
}

// LearnPattern stores a traffic pattern (user-agent, ASN, JA4H combo + behavioral signatures) as learned
// This builds up a knowledge base of known traffic patterns
func (f *FeedbackLoop) LearnPattern(userAgent, asn, ja4h, label string, labeledByUser bool, notes string) {
	f.LearnPatternWithBehavior(userAgent, asn, ja4h, label, labeledByUser, notes, 0, 0, false, false, false, nil)
}

// LearnPatternWithBehavior stores a traffic pattern with behavioral signatures
func (f *FeedbackLoop) LearnPatternWithBehavior(userAgent, asn, ja4h, label string, labeledByUser bool, notes string,
	pathDiversity float64, requestRate float64, hasPathPattern bool, hasTCPPattern bool, hasUDPPattern bool, signalTypes []string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Build a unique key for this pattern combination
	// We create multiple keys for partial matches:
	// 1. Full pattern: ua+asn+ja4h
	// 2. UA+ASN (most specific for non-TLS traffic)
	// 3. UA only (fallback)
	// 4. ASN only (for known good/bad networks)
	// 5. JA4H only (for TLS fingerprints)

	now := time.Now()
	patterns := make(map[string]LearnedPattern)

	// Full pattern (most specific)
	if userAgent != "" && asn != "" && ja4h != "" {
		key := "ua:" + userAgent + "|asn:" + asn + "|ja4h:" + ja4h
		patterns[key] = LearnedPattern{
			Key:                key,
			UserAgent:          userAgent,
			ASN:                asn,
			JA4H:               ja4h,
			Label:              label,
			Confidence:         1.0,
			ObservedCount:      1,
			FirstSeen:          now,
			LastSeen:           now,
			LabeledByUser:      labeledByUser,
			Notes:              notes,
			AvgPathDiversity:   pathDiversity,
			AvgRequestRate:     requestRate,
			HasPathPattern:     hasPathPattern,
			HasTCPPattern:      hasTCPPattern,
			HasUDPPattern:      hasUDPPattern,
			TypicalSignalTypes: signalTypes,
		}
	}

	// UA + ASN combo (good for identifying specific clients from known networks)
	if userAgent != "" && asn != "" {
		key := "ua:" + userAgent + "|asn:" + asn
		patterns[key] = LearnedPattern{
			Key:                key,
			UserAgent:          userAgent,
			ASN:                asn,
			Label:              label,
			Confidence:         0.9,
			ObservedCount:      1,
			FirstSeen:          now,
			LastSeen:           now,
			LabeledByUser:      labeledByUser,
			Notes:              notes,
			AvgPathDiversity:   pathDiversity,
			AvgRequestRate:     requestRate,
			HasPathPattern:     hasPathPattern,
			HasTCPPattern:      hasTCPPattern,
			HasUDPPattern:      hasUDPPattern,
			TypicalSignalTypes: signalTypes,
		}
	}

	// UA only (most common case for non-TLS HTTP traffic)
	if userAgent != "" {
		key := "ua:" + userAgent
		patterns[key] = LearnedPattern{
			Key:                key,
			UserAgent:          userAgent,
			Label:              label,
			Confidence:         0.7,
			ObservedCount:      1,
			FirstSeen:          now,
			LastSeen:           now,
			LabeledByUser:      labeledByUser,
			Notes:              notes,
			AvgPathDiversity:   pathDiversity,
			AvgRequestRate:     requestRate,
			HasPathPattern:     hasPathPattern,
			HasTCPPattern:      hasTCPPattern,
			HasUDPPattern:      hasUDPPattern,
			TypicalSignalTypes: signalTypes,
		}
	}

	// ASN only (for known good/bad autonomous systems)
	// Only learn ASN patterns if labeled by user (too broad for auto-learning)
	if asn != "" && labeledByUser {
		key := "asn:" + asn
		patterns[key] = LearnedPattern{
			Key:                key,
			ASN:                asn,
			Label:              label,
			Confidence:         0.5,
			ObservedCount:      1,
			FirstSeen:          now,
			LastSeen:           now,
			LabeledByUser:      labeledByUser,
			Notes:              notes,
			HasTCPPattern:      hasTCPPattern,
			HasUDPPattern:      hasUDPPattern,
			TypicalSignalTypes: signalTypes,
		}
	}

	// JA4H only (TLS fingerprint patterns)
	if ja4h != "" {
		key := "ja4h:" + ja4h
		patterns[key] = LearnedPattern{
			Key:                key,
			JA4H:               ja4h,
			Label:              label,
			Confidence:         0.8,
			ObservedCount:      1,
			FirstSeen:          now,
			LastSeen:           now,
			LabeledByUser:      labeledByUser,
			Notes:              notes,
			AvgRequestRate:     requestRate,
			HasTCPPattern:      hasTCPPattern,
			HasUDPPattern:      hasUDPPattern,
			TypicalSignalTypes: signalTypes,
		}
	}

	// Store or update patterns
	patternsLearned := 0
	for key, newPattern := range patterns {
		if existing, exists := f.learnedPatterns[key]; exists {
			// Update existing pattern
			existing.ObservedCount++
			existing.LastSeen = now

			// If labels match, increase confidence
			if existing.Label == label {
				existing.Confidence = math.Min(1.0, existing.Confidence+0.05)
				existing.TruePositiveCount++

				// Update behavioral metrics (running average)
				if pathDiversity > 0 {
					existing.AvgPathDiversity = (existing.AvgPathDiversity*float64(existing.ObservedCount-1) + pathDiversity) / float64(existing.ObservedCount)
				}
				if requestRate > 0 {
					existing.AvgRequestRate = (existing.AvgRequestRate*float64(existing.ObservedCount-1) + requestRate) / float64(existing.ObservedCount)
				}
				if hasPathPattern {
					existing.HasPathPattern = true
				}
				if hasTCPPattern {
					existing.HasTCPPattern = true
				}
				if hasUDPPattern {
					existing.HasUDPPattern = true
				}
				// Merge signal types
				if len(signalTypes) > 0 {
					existing.TypicalSignalTypes = mergeUniqueStrings(existing.TypicalSignalTypes, signalTypes)
				}
			} else {
				// Conflicting labels - reduce confidence
				existing.Confidence = math.Max(0.1, existing.Confidence-0.1)
				existing.FalsePositiveCount++
				logrus.WithFields(logrus.Fields{
					"key":            key,
					"existing_label": existing.Label,
					"new_label":      label,
				}).Warn("Pattern label conflict - reducing confidence")
			}

			// User labels override auto-learned ones
			if labeledByUser && !existing.LabeledByUser {
				existing.Label = label
				existing.LabeledByUser = true
				existing.Notes = notes
				logrus.WithField("key", key).Info("User label overrode auto-learned pattern")
			}

			// Cap observation count
			if existing.ObservedCount > f.patternMaxObserved {
				existing.ObservedCount = f.patternMaxObserved
			}

			f.learnedPatterns[key] = existing
		} else {
			// New pattern
			f.learnedPatterns[key] = newPattern
			patternsLearned++
		}
	}

	if patternsLearned > 0 {
		logrus.WithFields(logrus.Fields{
			"patterns_learned": patternsLearned,
			"user_agent":       userAgent,
			"asn":              asn,
			"ja4h":             ja4h,
			"label":            label,
			"user_labeled":     labeledByUser,
		}).Info("Learned new traffic patterns")

		// Save patterns to disk
		go f.savePatterns()
	}
}

// CheckPattern checks if traffic matches a learned pattern
// Returns (matched, label, confidence, pattern_key)
func (f *FeedbackLoop) CheckPattern(userAgent, asn, ja4h string) (bool, string, float64, string) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check patterns in order of specificity (most specific first)
	checkOrder := []string{
		"ua:" + userAgent + "|asn:" + asn + "|ja4h:" + ja4h, // Full pattern
		"ua:" + userAgent + "|asn:" + asn,                   // UA + ASN
		"ja4h:" + ja4h,                                      // JA4H only
		"ua:" + userAgent,                                   // UA only
		"asn:" + asn,                                        // ASN only (broadest)
	}

	for _, key := range checkOrder {
		if pattern, exists := f.learnedPatterns[key]; exists {
			// Only trust patterns with sufficient confidence
			if pattern.Confidence >= 0.5 {
				return true, pattern.Label, pattern.Confidence, key
			}
		}
	}

	return false, "", 0.0, ""
}

// GetLearnedPatterns returns all learned patterns (for debugging/export)
func (f *FeedbackLoop) GetLearnedPatterns() []LearnedPattern {
	f.mu.RLock()
	defer f.mu.RUnlock()

	patterns := make([]LearnedPattern, 0, len(f.learnedPatterns))
	for _, pattern := range f.learnedPatterns {
		patterns = append(patterns, pattern)
	}
	return patterns
}

// RemovePattern removes a learned pattern
func (f *FeedbackLoop) RemovePattern(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.learnedPatterns, key)
	f.savePatterns()
	logrus.WithField("key", key).Info("Removed learned pattern")
}

// loadPatterns loads learned patterns from disk
func (f *FeedbackLoop) loadPatterns() {
	if f.patternsPath == "" {
		return
	}

	data, err := os.ReadFile(f.patternsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			logrus.WithError(err).Warn("Failed to load learned patterns from disk")
		}
		return
	}

	var patterns []LearnedPattern
	if err := json.Unmarshal(data, &patterns); err != nil {
		logrus.WithError(err).Error("Failed to parse learned patterns file")
		return
	}

	loaded := 0
	now := time.Now()
	for _, pattern := range patterns {
		// Check if pattern has expired (if TTL > 0)
		if f.patternsTTL > 0 && now.Sub(pattern.LastSeen) > f.patternsTTL {
			continue // Skip expired patterns
		}

		f.learnedPatterns[pattern.Key] = pattern
		loaded++
	}

	if loaded > 0 {
		logrus.WithFields(logrus.Fields{
			"loaded": loaded,
			"total":  len(patterns),
		}).Info("Loaded learned patterns from disk")
	}
}

// savePatterns saves learned patterns to disk
func (f *FeedbackLoop) savePatterns() {
	if f.patternsPath == "" {
		return
	}

	patterns := f.GetLearnedPatterns()
	data, err := json.MarshalIndent(patterns, "", "  ")
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal learned patterns")
		return
	}

	// Create directory if it doesn't exist
	dir := "/var/lib/packetyeeter"
	if err := os.MkdirAll(dir, 0755); err != nil {
		logrus.WithError(err).Warn("Failed to create persistence directory")
		return
	}

	if err := os.WriteFile(f.patternsPath, data, 0644); err != nil {
		logrus.WithError(err).Error("Failed to save learned patterns to disk")
		return
	}

	logrus.WithField("patterns", len(patterns)).Debug("Saved learned patterns to disk")
}

// mergeUniqueStrings merges two string slices removing duplicates
func mergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	// Limit to top 20 most common signal types
	if len(result) > 20 {
		result = result[:20]
	}

	return result
}

// ClearLearningWindow removes all learning labels
func (f *FeedbackLoop) ClearLearningWindow() int {
	// Fast atomic swap to minimize lock time
	f.mu.Lock()
	count := len(f.learningIPs)
	f.learningIPs = make(map[string]LearningLabel)
	f.mu.Unlock()

	logrus.WithField("count", count).Info("Cleared all learning window labels")
	return count
}

// BulkRemoveFromLearningWindow removes multiple IPs from learning window
func (f *FeedbackLoop) BulkRemoveFromLearningWindow(ips []string) int {
	if len(ips) == 0 {
		return 0
	}

	// Fast lock-minimizing approach
	f.mu.Lock()
	count := 0
	for _, ip := range ips {
		if _, exists := f.learningIPs[ip]; exists {
			delete(f.learningIPs, ip)
			count++
		}
	}
	f.mu.Unlock()

	if count > 0 {
		logrus.WithFields(logrus.Fields{
			"requested": len(ips),
			"removed":   count,
		}).Info("Bulk removed IPs from learning window")
	}

	return count
}

// GetLearningWindowIPs returns all IPs currently in the learning window
func (f *FeedbackLoop) GetLearningWindowIPs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	ips := make([]string, 0, len(f.learningIPs))
	for ip := range f.learningIPs {
		ips = append(ips, ip)
	}

	return ips
}

// IsInLearningWindow checks if an IP is in the learning window (lock-free check for hot path)
func (f *FeedbackLoop) IsInLearningWindow(ip string) bool {
	f.mu.RLock()
	_, exists := f.learningIPs[ip]
	f.mu.RUnlock()
	return exists
}
