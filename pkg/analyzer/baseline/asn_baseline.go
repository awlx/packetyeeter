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

	// converge holds the shadow candidate distributions used to converge the
	// baseline toward a sustained legitimate shift. Allocated lazily on the
	// first out-of-band sample; nil for the common case of a stable ASN.
	converge *convergenceState
}

// numBaselineShards controls how many independent lock domains the
// calibrator's ASN map is split across. RecordObservation (called for
// every incoming signal with TCP context, on the ingestion hot path) and
// CalculateAnomaly (called for every signal during AI-engine window
// evaluation, from up to Workers concurrent goroutines) both need to
// touch this map extremely frequently. A single global mutex here
// reintroduces the same class of contention already fixed once for the
// reputation manager: under sustained write pressure from many ASNs,
// Go's sync.RWMutex favors waiting writers over new readers, so readers
// (CalculateAnomaly) end up serialized behind writers (RecordObservation)
// even though both only ever touch one ASN's entry. Sharding by ASN keeps
// unrelated ASNs from contending with each other at all.
const numBaselineShards = 32

// baselineShard is one independent lock domain of the ASN map.
type baselineShard struct {
	mu        sync.RWMutex
	baselines map[string]*ASNBaseline // ASN -> baseline
}

// BaselineCalibrator manages ASN baselines
type BaselineCalibrator struct {
	shards [numBaselineShards]*baselineShard

	minObservations uint64        // Minimum observations before baseline is valid (default: 100)
	retentionPeriod time.Duration // How long to keep baselines (default: 7 days)

	cleanupInterval time.Duration
	maxBaselines    int
}

// shardFor returns the shard responsible for the given ASN. Using a hash
// of the ASN string (rather than e.g. round-robin) ensures the same ASN
// always maps to the same shard, which is required for correctness (all
// operations on one ASN must observe each other).
func (bc *BaselineCalibrator) shardFor(asn string) *baselineShard {
	// Inline FNV-1a: fnv.New32a() returns its state behind a hash.Hash32
	// interface and []byte(asn) escapes into the interface call, costing
	// two heap allocations per call — and this runs per signal via both
	// RecordObservation and CalculateAnomaly.
	h := uint32(2166136261)
	for i := 0; i < len(asn); i++ {
		h ^= uint32(asn[i])
		h *= 16777619
	}
	return bc.shards[h%numBaselineShards]
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
		minObservations: cfg.MinObservations,
		retentionPeriod: cfg.RetentionPeriod,
		cleanupInterval: cfg.CleanupInterval,
		maxBaselines:    100000,
	}
	for i := range bc.shards {
		bc.shards[i] = &baselineShard{baselines: make(map[string]*ASNBaseline)}
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

	shard := bc.shardFor(asn)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	baseline, ok := shard.baselines[asn]
	if !ok {
		perShardMax := bc.maxBaselines / numBaselineShards
		if perShardMax < 1 || len(shard.baselines) >= perShardMax {
			return
		}
		baseline = &ASNBaseline{
			ASN:       asn,
			FirstSeen: obs.Timestamp,
		}
		shard.baselines[asn] = baseline
	}

	baseline.LastSeen = obs.Timestamp
	baseline.ObservationCount++

	// Increment metrics
	metrics.BaselineObservationsTotal.Inc()

	// Once a metric's baseline is past warmup, exclude samples that already
	// score as clearly anomalous against it from further folding into that
	// same baseline (self-poisoning guard - see baselineAnomalyZScoreThreshold).
	// During warmup (baseline.ObservationCount < minObservations) every
	// sample still folds in normally, same as before, so a fresh ASN can
	// calibrate from its initial (possibly mixed) traffic.
	warm := baseline.ObservationCount >= bc.minObservations
	if baseline.converge == nil {
		baseline.converge = &convergenceState{}
	}
	conv := baseline.converge

	// Update running statistics using Welford's algorithm (see pkg/utils/stats)
	if obs.TTL > 0 {
		foldMetric(&baseline.TTL, &conv.ttl, float64(obs.TTL), obs.Timestamp, warm)
	}
	if obs.WindowSize > 0 {
		foldMetric(&baseline.WindowSize, &conv.windowSize, float64(obs.WindowSize), obs.Timestamp, warm)
	}
	if obs.PacketSize > 0 {
		foldMetric(&baseline.PacketSize, &conv.packetSize, float64(obs.PacketSize), obs.Timestamp, warm)
	}
	if obs.RequestRate > 0 {
		foldMetric(&baseline.RequestRate, &conv.requestRate, obs.RequestRate, obs.Timestamp, warm)
	}
	if obs.SignalRate >= 0 {
		foldMetric(&baseline.SignalRate, &conv.signalRate, obs.SignalRate, obs.Timestamp, warm)
	}
	if obs.ConnTime > 0 {
		foldMetric(&baseline.ConnTime, &conv.connTime, obs.ConnTime, obs.Timestamp, warm)
	}
	if obs.HandshakeRTT > 0 {
		foldMetric(&baseline.HandshakeRTT, &conv.handshakeRTT, obs.HandshakeRTT, obs.Timestamp, warm)
	}
	if obs.PacketRate > 0 {
		foldMetric(&baseline.PacketRate, &conv.packetRate, obs.PacketRate, obs.Timestamp, warm)
	}
	if obs.ByteRate > 0 {
		foldMetric(&baseline.ByteRate, &conv.byteRate, obs.ByteRate, obs.Timestamp, warm)
	}
}

// baselineAnomalyZScoreThreshold matches AnomalyScore.IsAnomalous's 3-sigma
// cutoff. Once a per-metric baseline is warm, a sample that already scores
// at or beyond this many standard deviations from it is excluded from
// folding into that same baseline, so a sustained attack can't keep
// dragging the baseline it's scored against toward its own attack rate
// (self-poisoning). This only ever excludes individual metric updates, never
// the observation as a whole: ObservationCount/LastSeen above still advance
// normally, and other metrics on the same observation are evaluated
// independently.
const baselineAnomalyZScoreThreshold = 3.0

// A legitimate ASN can permanently shift its behavior (new egress hardware,
// new region, migrated services), which changes a metric's true mean. The
// self-poisoning guard above would then reject the new normal as >3 sigma
// forever - the baseline never converges and every request from that ASN scores
// anomalous indefinitely. These constants gate a controlled convergence: the
// rejected samples are folded into a shadow "candidate" distribution, and only
// once that candidate is BOTH long-lived and self-consistent does it replace
// the stale baseline. The gates are deliberately strict so a transient attack -
// which ends long before the duration/sample thresholds - can never converge
// the baseline to its own rate; a genuine permanent shift eventually will.
const (
	// convergenceMinSamples is how many coherent out-of-band samples the
	// candidate must accumulate before it can be adopted.
	convergenceMinSamples = 300
	// convergenceMinDuration is how long the shifted regime must persist
	// (wall-clock, by observation timestamps) before adoption. A DDoS that
	// sustains a coherent rate for this long is pathological; a legitimate
	// shift is permanent and clears it easily.
	convergenceMinDuration = 30 * time.Minute
	// convergenceMaxSpreadZ bounds how far a new anomalous sample may sit from
	// the candidate it is building and still count toward it. Incoherent
	// anomalies (a varied/noisy attack) reset the candidate instead of
	// accumulating, so only a genuinely stable new regime converges.
	convergenceMaxSpreadZ = 3.0
)

// metricCandidate is the shadow distribution of samples that are anomalous
// against the current baseline but may represent a sustained legitimate shift.
type metricCandidate struct {
	shadow    RunningStats
	firstFold time.Time
}

// convergenceState holds one candidate per tracked metric. It is allocated
// lazily (only when a warm baseline first rejects a sample) so ASNs that never
// drift cost nothing extra.
type convergenceState struct {
	ttl          metricCandidate
	windowSize   metricCandidate
	packetSize   metricCandidate
	requestRate  metricCandidate
	signalRate   metricCandidate
	connTime     metricCandidate
	handshakeRTT metricCandidate
	packetRate   metricCandidate
	byteRate     metricCandidate
}

// foldMetric updates main via Welford's algorithm, applying the self-poisoning
// guard and, when a warm baseline rejects a sample, the controlled-convergence
// path through the metric's candidate shadow.
func foldMetric(main *RunningStats, cand *metricCandidate, value float64, timestamp time.Time, warm bool) {
	if warm && main.Count >= 2 {
		if z := main.ZScore(value); math.Abs(z) > baselineAnomalyZScoreThreshold {
			foldCandidate(main, cand, value, timestamp)
			return
		}
	}
	// The sample fits the current baseline: the regime is stable, so any
	// partially-built candidate was transient (a burst/attack that has ended).
	// Discard it and fold the sample normally.
	*cand = metricCandidate{}
	stats.UpdateRunningStats(main, value, timestamp)
}

// foldCandidate accumulates an out-of-band sample into the candidate shadow and,
// once the candidate is long-lived and self-consistent, adopts it as the new
// baseline.
func foldCandidate(main *RunningStats, cand *metricCandidate, value float64, timestamp time.Time) {
	// If the candidate already has shape but this sample is incoherent with it,
	// restart the candidate from this sample - we always track the most recent
	// coherent regime, not an average of unrelated anomalies.
	if cand.shadow.Count >= 2 {
		if z := cand.shadow.ZScore(value); math.Abs(z) > convergenceMaxSpreadZ {
			*cand = metricCandidate{}
		}
	}
	if cand.shadow.Count == 0 {
		cand.firstFold = timestamp
	}
	stats.UpdateRunningStats(&cand.shadow, value, timestamp)

	// Adopt only when the candidate is both well-populated AND has persisted
	// long enough to rule out a transient attack.
	if cand.shadow.Count >= convergenceMinSamples &&
		!cand.firstFold.IsZero() &&
		timestamp.Sub(cand.firstFold) >= convergenceMinDuration {
		*main = cand.shadow
		*cand = metricCandidate{}
		metrics.BaselineObservationsTotal.Inc() // count the convergence as activity
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
	shard := bc.shardFor(asn)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	result := AnomalyScore{
		ASN: asn,
	}

	baseline, ok := shard.baselines[asn]
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

	// Find max absolute z-score without allocating a slice per call (this
	// runs per signal on the hot path).
	result.MaxZScore = max(
		math.Abs(result.TTLZScore),
		math.Abs(result.WindowSizeZScore),
		math.Abs(result.PacketSizeZScore),
		math.Abs(result.RequestRateZScore),
		math.Abs(result.SignalRateZScore),
		math.Abs(result.ConnTimeZScore),
		math.Abs(result.HandshakeRTTZScore),
		math.Abs(result.PacketRateZScore),
		math.Abs(result.ByteRateZScore),
	)

	return result
}

// IsAnomalous checks if the anomaly score exceeds the threshold
func (as *AnomalyScore) IsAnomalous() bool {
	return as.IsBaselineValid && as.MaxZScore > 3.0 // 3 standard deviations
}

// GetBaseline returns the baseline for an ASN
func (bc *BaselineCalibrator) GetBaseline(asn string) *ASNBaseline {
	shard := bc.shardFor(asn)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	if baseline, ok := shard.baselines[asn]; ok {
		// Return a copy to avoid race conditions
		baselineCopy := *baseline
		return &baselineCopy
	}

	return nil
}

// GetStats returns calibrator statistics
func (bc *BaselineCalibrator) GetStats() (calibratedASNs int, totalObservations uint64) {
	for _, shard := range bc.shards {
		shard.mu.RLock()
		for _, baseline := range shard.baselines {
			if baseline.ObservationCount >= bc.minObservations {
				calibratedASNs++
			}
			totalObservations += baseline.ObservationCount
		}
		shard.mu.RUnlock()
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

// cleanup removes baselines that haven't been updated recently. Each shard
// is locked independently so a cleanup pass never blocks the entire
// calibrator - only the one shard being swept at a time.
func (bc *BaselineCalibrator) cleanup() {
	now := time.Now()
	cutoff := now.Add(-bc.retentionPeriod)

	calibratedCount := 0
	for _, shard := range bc.shards {
		shard.mu.Lock()
		for asn, baseline := range shard.baselines {
			if baseline.LastSeen.Before(cutoff) {
				delete(shard.baselines, asn)
			}
		}
		for _, baseline := range shard.baselines {
			if baseline.ObservationCount >= bc.minObservations {
				calibratedCount++
			}
		}
		shard.mu.Unlock()
	}

	// Update metric for calibrated ASNs (those with enough observations)
	metrics.BaselineCalibratedASNs.Set(float64(calibratedCount))
}
