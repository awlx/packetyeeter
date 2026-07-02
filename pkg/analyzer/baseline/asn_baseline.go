package baseline

import (
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/utils/stats"
	"math"
	"sync"
	"time"
)

// ObservationData contains metrics observed for a single request/connection
type ObservationData struct {
	TTL          uint8
	WindowSize   uint16
	PacketSize   uint16
	RequestRate  float64
	SignalRate   float64
	ConnTime     float64 // Connection duration in seconds
	HandshakeRTT float64 // RTT in milliseconds
	PacketRate   float64 // Packets per second
	ByteRate     float64 // Bytes per second
	Timestamp    time.Time
}

// RunningStats is an alias for stats.RunningStats.
// This package uses Welford's online algorithm for running statistics.
// See pkg/utils/stats package documentation for when to use online vs post-hoc statistics.
type RunningStats = stats.RunningStats

// ASNBaseline tracks behavioral baseline for a single ASN
type ASNBaseline struct {
	ASN              string
	FirstSeen        time.Time
	LastSeen         time.Time
	ObservationCount uint64

	// Per-metric running statistics
	TTL          RunningStats
	WindowSize   RunningStats
	PacketSize   RunningStats
	RequestRate  RunningStats
	SignalRate   RunningStats
	ConnTime     RunningStats
	HandshakeRTT RunningStats
	PacketRate   RunningStats
	ByteRate     RunningStats
}

// BaselineCalibrator manages ASN baselines
type BaselineCalibrator struct {
	mu sync.RWMutex

	baselines map[string]*ASNBaseline // ASN -> baseline

	minObservations uint64        // Minimum observations before baseline is valid (default: 100)
	retentionPeriod time.Duration // How long to keep baselines (default: 7 days)

	lastCleanup     time.Time
	cleanupInterval time.Duration
}

// Config holds configuration for the baseline calibrator
type Config struct {
	MinObservations uint64
	RetentionPeriod time.Duration
	CleanupInterval time.Duration
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		MinObservations: 100,
		RetentionPeriod: 7 * 24 * time.Hour, // 7 days
		CleanupInterval: 1 * time.Hour,
	}
}

// NewBaselineCalibrator creates a new ASN baseline calibrator
func NewBaselineCalibrator(cfg Config) *BaselineCalibrator {
	if cfg.MinObservations == 0 {
		cfg = DefaultConfig()
	}

	bc := &BaselineCalibrator{
		baselines:       make(map[string]*ASNBaseline),
		minObservations: cfg.MinObservations,
		retentionPeriod: cfg.RetentionPeriod,
		cleanupInterval: cfg.CleanupInterval,
		lastCleanup:     time.Now(),
	}

	// Start cleanup goroutine
	go bc.cleanupLoop()

	return bc
}

// RecordObservation records a new observation for an ASN
func (bc *BaselineCalibrator) RecordObservation(asn string, obs ObservationData) {
	if asn == "" || asn == "unknown" || asn == "Unknown" {
		return
	}

	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()

	baseline, ok := bc.baselines[asn]
	if !ok {
		baseline = &ASNBaseline{
			ASN:       asn,
			FirstSeen: obs.Timestamp,
		}
		bc.baselines[asn] = baseline
	}

	baseline.LastSeen = obs.Timestamp
	baseline.ObservationCount++

	// Increment metrics
	metrics.BaselineObservationsTotal.Inc()

	// Update running statistics using Welford's algorithm (see pkg/utils/stats)
	if obs.TTL > 0 {
		stats.UpdateRunningStats(&baseline.TTL, float64(obs.TTL), obs.Timestamp)
	}
	if obs.WindowSize > 0 {
		stats.UpdateRunningStats(&baseline.WindowSize, float64(obs.WindowSize), obs.Timestamp)
	}
	if obs.PacketSize > 0 {
		stats.UpdateRunningStats(&baseline.PacketSize, float64(obs.PacketSize), obs.Timestamp)
	}
	if obs.RequestRate > 0 {
		stats.UpdateRunningStats(&baseline.RequestRate, obs.RequestRate, obs.Timestamp)
	}
	if obs.SignalRate >= 0 {
		stats.UpdateRunningStats(&baseline.SignalRate, obs.SignalRate, obs.Timestamp)
	}
	if obs.ConnTime > 0 {
		stats.UpdateRunningStats(&baseline.ConnTime, obs.ConnTime, obs.Timestamp)
	}
	if obs.HandshakeRTT > 0 {
		stats.UpdateRunningStats(&baseline.HandshakeRTT, obs.HandshakeRTT, obs.Timestamp)
	}
	if obs.PacketRate > 0 {
		stats.UpdateRunningStats(&baseline.PacketRate, obs.PacketRate, obs.Timestamp)
	}
	if obs.ByteRate > 0 {
		stats.UpdateRunningStats(&baseline.ByteRate, obs.ByteRate, obs.Timestamp)
	}
}

// AnomalyScore contains z-scores for all metrics
type AnomalyScore struct {
	ASN              string
	IsBaselineValid  bool // Whether enough observations exist
	ObservationCount uint64

	// Z-scores for each metric (how many standard deviations from mean)
	TTLZScore          float64
	WindowSizeZScore   float64
	PacketSizeZScore   float64
	RequestRateZScore  float64
	SignalRateZScore   float64
	ConnTimeZScore     float64
	HandshakeRTTZScore float64
	PacketRateZScore   float64
	ByteRateZScore     float64

	// Max absolute z-score across all metrics
	MaxZScore float64
}

// CalculateAnomaly calculates z-scores for an observation against the baseline
func (bc *BaselineCalibrator) CalculateAnomaly(asn string, obs ObservationData) AnomalyScore {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	result := AnomalyScore{
		ASN: asn,
	}

	baseline, ok := bc.baselines[asn]
	if !ok || baseline.ObservationCount < bc.minObservations {
		result.IsBaselineValid = false
		return result
	}

	result.IsBaselineValid = true
	result.ObservationCount = baseline.ObservationCount

	// Calculate z-scores for each metric using stats utility
	if obs.TTL > 0 && baseline.TTL.Count > 0 {
		result.TTLZScore = baseline.TTL.ZScore(float64(obs.TTL))
	}
	if obs.WindowSize > 0 && baseline.WindowSize.Count > 0 {
		result.WindowSizeZScore = baseline.WindowSize.ZScore(float64(obs.WindowSize))
	}
	if obs.PacketSize > 0 && baseline.PacketSize.Count > 0 {
		result.PacketSizeZScore = baseline.PacketSize.ZScore(float64(obs.PacketSize))
	}
	if obs.RequestRate > 0 && baseline.RequestRate.Count > 0 {
		result.RequestRateZScore = baseline.RequestRate.ZScore(obs.RequestRate)
	}
	if obs.SignalRate >= 0 && baseline.SignalRate.Count > 0 {
		result.SignalRateZScore = baseline.SignalRate.ZScore(obs.SignalRate)
	}
	if obs.ConnTime > 0 && baseline.ConnTime.Count > 0 {
		result.ConnTimeZScore = baseline.ConnTime.ZScore(obs.ConnTime)
	}
	if obs.HandshakeRTT > 0 && baseline.HandshakeRTT.Count > 0 {
		result.HandshakeRTTZScore = baseline.HandshakeRTT.ZScore(obs.HandshakeRTT)
	}
	if obs.PacketRate > 0 && baseline.PacketRate.Count > 0 {
		result.PacketRateZScore = baseline.PacketRate.ZScore(obs.PacketRate)
	}
	if obs.ByteRate > 0 && baseline.ByteRate.Count > 0 {
		result.ByteRateZScore = baseline.ByteRate.ZScore(obs.ByteRate)
	}

	// Find max absolute z-score
	zScores := []float64{
		math.Abs(result.TTLZScore),
		math.Abs(result.WindowSizeZScore),
		math.Abs(result.PacketSizeZScore),
		math.Abs(result.RequestRateZScore),
		math.Abs(result.SignalRateZScore),
		math.Abs(result.ConnTimeZScore),
		math.Abs(result.HandshakeRTTZScore),
		math.Abs(result.PacketRateZScore),
		math.Abs(result.ByteRateZScore),
	}

	for _, z := range zScores {
		if z > result.MaxZScore {
			result.MaxZScore = z
		}
	}

	return result
}

// IsAnomalous checks if the anomaly score exceeds the threshold
func (as *AnomalyScore) IsAnomalous() bool {
	return as.IsBaselineValid && as.MaxZScore > 3.0 // 3 standard deviations
}

// GetBaseline returns the baseline for an ASN
func (bc *BaselineCalibrator) GetBaseline(asn string) *ASNBaseline {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if baseline, ok := bc.baselines[asn]; ok {
		// Return a copy to avoid race conditions
		baselineCopy := *baseline
		return &baselineCopy
	}

	return nil
}

// GetStats returns calibrator statistics
func (bc *BaselineCalibrator) GetStats() (calibratedASNs int, totalObservations uint64) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	for _, baseline := range bc.baselines {
		if baseline.ObservationCount >= bc.minObservations {
			calibratedASNs++
		}
		totalObservations += baseline.ObservationCount
	}

	return
}

// cleanupLoop periodically removes old baselines
func (bc *BaselineCalibrator) cleanupLoop() {
	ticker := time.NewTicker(bc.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		bc.cleanup()
	}
}

// cleanup removes baselines that haven't been updated recently
func (bc *BaselineCalibrator) cleanup() {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-bc.retentionPeriod)

	for asn, baseline := range bc.baselines {
		if baseline.LastSeen.Before(cutoff) {
			delete(bc.baselines, asn)
		}
	}

	// Update metric for calibrated ASNs (those with enough observations)
	calibratedCount := 0
	for _, baseline := range bc.baselines {
		if baseline.ObservationCount >= uint64(bc.minObservations) {
			calibratedCount++
		}
	}
	metrics.BaselineCalibratedASNs.Set(float64(calibratedCount))

	bc.lastCleanup = now
}
