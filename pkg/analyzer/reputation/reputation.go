package reputation

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	appmetrics "PacketYeeter/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

const (
	defaultMaxEntries  = 500000
	defaultMaxEntryAge = 24 * time.Hour
	defaultMaxASNHosts = 5000
)

var (
	ReputationScore = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_reputation_score",
		Help: "Current reputation score for an entity",
	}, []string{"type", "key"}) // type=ip, ja4, or asn

	ReputationEntryCounts = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packetyeeter_reputation_entries_total",
		Help: "Number of reputation entries by type",
	}, []string{"type"})
)

func setReputationScore(keyType EntityType, key string, score float64) {
	if appmetrics.IsHighCardinalityEnabled() {
		ReputationScore.WithLabelValues(string(keyType), key).Set(score)
	}
}

type EntityType string

const (
	TypeIP  EntityType = "ip"
	TypeJA4 EntityType = "ja4"
	TypeASN EntityType = "asn"
	TypeUA  EntityType = "ua"
)

type Entry struct {
	Score     float64
	FirstSeen time.Time
	LastSeen  time.Time
	Offenses  int
}

type asnStats struct {
	Seen      map[string]struct{}
	Offenders map[string]struct{}
}

type Engine struct {
	mu           sync.RWMutex
	entries      map[string]*Entry
	asnStats     map[string]*asnStats
	asnScoreCap  float64
	ipScoreCap   float64
	ja4ScoreCap  float64
	decayTick    *time.Ticker
	decayFactor  float64 // Multiplier per tick (e.g., 0.95)
	banThreshold float64
	stop         chan struct{}

	maxEntries  int
	maxEntryAge time.Duration
	maxASNHosts int
}

// New creates a reputation engine. Each decay tick multiplies scores by
// decayFactor; for example, a 5 minute interval with factor 0.95 has a score
// half-life of about 67.6 minutes.
func New(decayInterval time.Duration, decayFactor float64, banThreshold float64) *Engine {
	return &Engine{
		entries:      make(map[string]*Entry),
		asnStats:     make(map[string]*asnStats),
		asnScoreCap:  math.Inf(1),
		decayTick:    time.NewTicker(decayInterval),
		decayFactor:  decayFactor,
		banThreshold: banThreshold,
		stop:         make(chan struct{}),
		maxEntries:   defaultMaxEntries,
		maxEntryAge:  defaultMaxEntryAge,
		maxASNHosts:  defaultMaxASNHosts,
	}
}

// DecayHalfLife returns the duration for a score to decay by half under the
// configured interval and factor. A non-positive duration means decay is not
// configured; a factor outside (0,1) has no finite half-life.
func (e *Engine) DecayHalfLife(decayInterval time.Duration) time.Duration {
	if decayInterval <= 0 || e.decayFactor <= 0 || e.decayFactor >= 1 {
		return 0
	}
	return time.Duration(math.Log(0.5) / math.Log(e.decayFactor) * float64(decayInterval))
}

func (e *Engine) SetASNScoreCap(cap float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.asnScoreCap = cap
	for k, entry := range e.entries {
		if len(k) > len(TypeASN)+1 && k[:len(TypeASN)+1] == string(TypeASN)+":" && entry.Score > cap {
			entry.Score = cap
			// key format: TypeASN:key
			setReputationScore(TypeASN, k[len(TypeASN)+1:], entry.Score)
		}
	}
}

func (e *Engine) SetIPScoreCap(cap float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ipScoreCap = cap
	for k, entry := range e.entries {
		if len(k) > len(TypeIP)+1 && k[:len(TypeIP)+1] == string(TypeIP)+":" && entry.Score > cap {
			entry.Score = cap
			setReputationScore(TypeIP, k[len(TypeIP)+1:], entry.Score)
		}
	}
}

func (e *Engine) SetJA4ScoreCap(cap float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ja4ScoreCap = cap
	for k, entry := range e.entries {
		if len(k) > len(TypeJA4)+1 && k[:len(TypeJA4)+1] == string(TypeJA4)+":" && entry.Score > cap {
			entry.Score = cap
			setReputationScore(TypeJA4, k[len(TypeJA4)+1:], entry.Score)
		}
	}
}

func (e *Engine) SetMaxEntries(max int) {
	if max <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxEntries = max
}

func (e *Engine) SetMaxEntryAge(age time.Duration) {
	if age <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxEntryAge = age
}

func (e *Engine) SetMaxASNHosts(max int) {
	if max <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxASNHosts = max
}

func (e *Engine) Start() {
	go func() {
		for {
			select {
			case <-e.stop:
				return
			case <-e.decayTick.C:
				e.decay()
			}
		}
	}()
}

func (e *Engine) Stop() {
	e.decayTick.Stop()
	close(e.stop)
}

// Penalize increases the score of a key (IP, JA4, ASN)
func (e *Engine) Penalize(key string, keyType EntityType, weight float64, reason string) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.penalizeLocked(key, keyType, weight, reason)
}

func (e *Engine) penalizeLocked(key string, keyType EntityType, weight float64, reason string) float64 {
	storeKey := string(keyType) + ":" + key
	entry, exists := e.entries[storeKey]

	if !exists {
		entry = &Entry{
			FirstSeen: time.Now(),
		}
		e.entries[storeKey] = entry
	}

	entry.Score += weight
	switch keyType {
	case TypeIP:
		if entry.Score > e.ipScoreCap {
			entry.Score = e.ipScoreCap
		}
	case TypeJA4:
		if entry.Score > e.ja4ScoreCap {
			entry.Score = e.ja4ScoreCap
		}
	}
	entry.LastSeen = time.Now()
	entry.Offenses++

	if entry.Score >= e.banThreshold && (entry.Score-weight) < e.banThreshold {
		logrus.WithFields(logrus.Fields{
			"key":    key,
			"type":   keyType,
			"score":  entry.Score,
			"reason": reason,
		}).Warn("Reputation Threshold Exceeded: Entity marked as Bad Actor")
	}

	// Update Metric
	setReputationScore(keyType, key, entry.Score)

	// Skip building the Fields map (an allocation) when debug logging is
	// disabled — logrus.WithFields() always allocates/copies the map
	// eagerly even if the resulting Debug() call is a no-op. This runs
	// under e.mu for every Penalize call (up to several per signal across
	// all AI-engine workers), so the allocation cost is paid while
	// serializing all callers on the same lock.
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(logrus.Fields{
			"key":    key,
			"type":   keyType,
			"added":  weight,
			"total":  entry.Score,
			"reason": reason,
		}).Debug("Reputation Penalized")
	}

	e.pruneIfNeededLocked(time.Now())

	return entry.Score
}

// ObserveIP tracks a unique IP seen for an ASN (used for normalization)
func (e *Engine) ObserveIP(asn string, ip string) {
	if asn == "" || ip == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	stats := e.getASNStatsLocked(asn)
	stats.Seen[ip] = struct{}{}
	e.boundASNStatsLocked(stats)
}

// PenalizeASN scales the ASN penalty by the ratio of offending IPs to total IPs seen for that ASN
func (e *Engine) PenalizeASN(asn string, ip string, baseWeight float64, reason string) float64 {
	if asn == "" {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	stats := e.getASNStatsLocked(asn)
	if ip != "" {
		stats.Seen[ip] = struct{}{}
		stats.Offenders[ip] = struct{}{}
		e.boundASNStatsLocked(stats)
	}
	offenders := len(stats.Offenders)
	total := len(stats.Seen)
	if total == 0 {
		total = 1
	}
	// Soften ratios for small populations to avoid instant ASN nukes
	if total < 50 {
		total = 50
	}
	ratio := float64(offenders) / float64(total)
	weight := baseWeight * ratio
	return e.penalizeASNLocked(asn, weight, fmt.Sprintf("%s (ratio=%.4f offenders=%d total=%d)", reason, ratio, offenders, total))
}

// RecordSignal atomically applies the IP, ASN, and JA4H reputation
// penalties for a single detection signal under one lock acquisition,
// instead of the equivalent sequence of Penalize/ObserveIP/PenalizeASN/
// Penalize calls (up to four separate lock/unlock round trips). Under the
// AI detection engine's per-worker signal processing (see
// aidetection.Engine.processSignal), every signal calls into reputation
// tracking, so serializing many short, independent lock acquisitions
// across all workers adds contention that a single combined critical
// section avoids. Semantics match calling ObserveIP then PenalizeASN: the
// IP is recorded as both seen and an offender for the ASN, and the ASN
// penalty is scaled by the offender/total ratio exactly as before.
//
// ip and asnWeight are ignored (no-op) when the respective key ("" for ip
// or asn) is empty, matching the guards in the individual methods.
func (e *Engine) RecordSignal(ip string, ipWeight float64, asn string, asnWeight float64, ja4h string, ja4Weight float64, reason string) (ipScore, asnScore float64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if ip != "" {
		ipScore = e.penalizeLocked(ip, TypeIP, ipWeight, reason)
	}

	if asn != "" {
		stats := e.getASNStatsLocked(asn)
		if ip != "" {
			stats.Seen[ip] = struct{}{}
			stats.Offenders[ip] = struct{}{}
			e.boundASNStatsLocked(stats)
		}
		offenders := len(stats.Offenders)
		total := len(stats.Seen)
		if total == 0 {
			total = 1
		}
		// Soften ratios for small populations to avoid instant ASN nukes
		if total < 50 {
			total = 50
		}
		ratio := float64(offenders) / float64(total)
		weight := asnWeight * ratio
		asnScore = e.penalizeASNLocked(asn, weight, fmt.Sprintf("%s (ratio=%.4f offenders=%d total=%d)", reason, ratio, offenders, total))
	}

	if ja4h != "" {
		e.penalizeLocked(ja4h, TypeJA4, ja4Weight, reason)
	}

	return ipScore, asnScore
}

// RewardASN decreases the ASN score based on good traffic ratio
func (e *Engine) RewardIP(ip string, baseWeight float64, reason string) float64 {
	if ip == "" {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rewardLocked(ip, TypeIP, baseWeight, reason)
}

func (e *Engine) RewardJA4(ja4 string, baseWeight float64, reason string) float64 {
	if ja4 == "" {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rewardLocked(ja4, TypeJA4, baseWeight, reason)
}

func (e *Engine) rewardLocked(key string, keyType EntityType, weight float64, reason string) float64 {
	storeKey := string(keyType) + ":" + key
	entry, exists := e.entries[storeKey]
	if !exists || entry.Score <= 0 {
		return 0
	}
	// Dampen repeated adjustments
	dampen := 1.0 / math.Sqrt(float64(entry.Offenses)+1)
	weight = weight * dampen
	if weight > entry.Score {
		weight = entry.Score
	}
	entry.Score -= weight
	entry.LastSeen = time.Now()
	// Offenses unchanged for reward; it tracks detections

	setReputationScore(keyType, key, entry.Score)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(logrus.Fields{
			"key":    key,
			"type":   keyType,
			"added":  -weight,
			"total":  entry.Score,
			"reason": reason,
		}).Debug("Reputation Rewarded")
	}

	return entry.Score
}

func (e *Engine) RewardASN(asn string, ip string, baseWeight float64, reason string) float64 {
	if asn == "" {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	stats := e.getASNStatsLocked(asn)
	if ip != "" {
		stats.Seen[ip] = struct{}{}
	}
	offenders := len(stats.Offenders)
	total := len(stats.Seen)
	if total == 0 {
		total = 1
	}
	good := total - offenders
	if good < 0 {
		good = 0
	}
	ratio := float64(good) / float64(total)
	weight := baseWeight * ratio
	return e.rewardASNLocked(asn, weight, fmt.Sprintf("%s (ratio=%.4f offenders=%d total=%d)", reason, ratio, offenders, total))
}

func (e *Engine) penalizeASNLocked(asn string, weight float64, reason string) float64 {
	storeKey := string(TypeASN) + ":" + asn
	entry, exists := e.entries[storeKey]
	if !exists {
		entry = &Entry{FirstSeen: time.Now()}
		e.entries[storeKey] = entry
	}
	// Dampen repeated offenses
	dampen := 1.0 / math.Sqrt(float64(entry.Offenses)+1)
	weight = weight * dampen
	entry.Score += weight
	if entry.Score > e.asnScoreCap {
		entry.Score = e.asnScoreCap
	}
	entry.LastSeen = time.Now()
	entry.Offenses++

	if entry.Score >= e.banThreshold && (entry.Score-weight) < e.banThreshold {
		logrus.WithFields(logrus.Fields{
			"key":    asn,
			"type":   TypeASN,
			"score":  entry.Score,
			"reason": reason,
		}).Warn("Reputation Threshold Exceeded: Entity marked as Bad Actor")
	}

	setReputationScore(TypeASN, asn, entry.Score)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(logrus.Fields{
			"key":    asn,
			"type":   TypeASN,
			"added":  weight,
			"total":  entry.Score,
			"reason": reason,
		}).Debug("Reputation Penalized")
	}

	return entry.Score
}

func (e *Engine) rewardASNLocked(asn string, weight float64, reason string) float64 {
	storeKey := string(TypeASN) + ":" + asn
	entry, exists := e.entries[storeKey]
	if !exists || entry.Score <= 0 {
		return 0
	}
	// Dampen repeated adjustments
	dampen := 1.0 / math.Sqrt(float64(entry.Offenses)+1)
	weight = weight * dampen
	if weight > entry.Score {
		weight = entry.Score
	}
	entry.Score -= weight
	entry.LastSeen = time.Now()
	// Offenses unchanged for reward; it tracks detections

	setReputationScore(TypeASN, asn, entry.Score)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(logrus.Fields{
			"key":    asn,
			"type":   TypeASN,
			"added":  -weight,
			"total":  entry.Score,
			"reason": reason,
		}).Debug("Reputation Rewarded")
	}

	return entry.Score
}

func (e *Engine) GetASNStats(asn string) (total int, offenders int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if stats, ok := e.asnStats[asn]; ok {
		return len(stats.Seen), len(stats.Offenders)
	}
	return 0, 0
}

func (e *Engine) getASNStatsLocked(asn string) *asnStats {
	stats, ok := e.asnStats[asn]
	if !ok {
		stats = &asnStats{Seen: make(map[string]struct{}), Offenders: make(map[string]struct{})}
		e.asnStats[asn] = stats
	}
	return stats
}

func (e *Engine) boundASNStatsLocked(stats *asnStats) {
	if e.maxASNHosts <= 0 {
		return
	}
	if len(stats.Seen) > e.maxASNHosts {
		excess := len(stats.Seen) - e.maxASNHosts
		i := 0
		for k := range stats.Seen {
			delete(stats.Seen, k)
			i++
			if i >= excess {
				break
			}
		}
	}
	if len(stats.Offenders) > e.maxASNHosts {
		excess := len(stats.Offenders) - e.maxASNHosts
		i := 0
		for k := range stats.Offenders {
			delete(stats.Offenders, k)
			i++
			if i >= excess {
				break
			}
		}
	}
}

// IsBad checks if the score exceeds the threshold
func (e *Engine) IsBad(key string, keyType EntityType) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	storeKey := string(keyType) + ":" + key
	if entry, ok := e.entries[storeKey]; ok {
		return entry.Score >= e.banThreshold
	}
	return false
}

// GetScore returns the raw score
func (e *Engine) GetScore(key string, keyType EntityType) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	storeKey := string(keyType) + ":" + key
	if entry, ok := e.entries[storeKey]; ok {
		return entry.Score
	}
	return 0
}

// GetEntry returns the full entry for inspection
func (e *Engine) GetEntry(key string) *Entry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for k, v := range e.entries {
		if strings.HasSuffix(k, ":"+key) {
			return v
		}
	}
	return nil
}

// GetBadEntries returns a map of bad actors (Type:Key format)
func (e *Engine) GetBadEntries() map[string]float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	bad := make(map[string]float64)
	for k, v := range e.entries {
		if v.Score >= e.banThreshold {
			bad[k] = v.Score
		}
	}
	return bad
}

// GetAllEntries returns a copy of all reputation entries
func (e *Engine) GetAllEntries() map[string]*Entry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	copy := make(map[string]*Entry)
	for k, v := range e.entries {
		// Deep copy entry to avoid race conditions if caller modifies it
		eVal := *v
		copy[k] = &eVal
	}
	return copy
}

func (e *Engine) decay() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	counts := map[EntityType]int{}

	for k, entry := range e.entries {
		entry.Score *= e.decayFactor

		if e.maxEntryAge > 0 && now.Sub(entry.LastSeen) > e.maxEntryAge {
			delete(e.entries, k)
			continue
		}
		if entry.Score < 0.1 {
			// Cleanup low scores to save memory
			delete(e.entries, k)
			continue
		}

		t := entityTypeFromKey(k)
		counts[t]++
	}

	e.pruneIfNeededLocked(now)

	for t, c := range counts {
		ReputationEntryCounts.WithLabelValues(string(t)).Set(float64(c))
	}
}

func (e *Engine) pruneIfNeededLocked(now time.Time) {
	if e.maxEntries <= 0 || len(e.entries) <= e.maxEntries {
		return
	}

	excess := len(e.entries) - e.maxEntries
	type kv struct {
		key      string
		lastSeen time.Time
	}
	arr := make([]kv, 0, len(e.entries))
	for k, v := range e.entries {
		arr = append(arr, kv{key: k, lastSeen: v.LastSeen})
	}
	sort.Slice(arr, func(i, j int) bool {
		return arr[i].lastSeen.Before(arr[j].lastSeen)
	})
	if excess > len(arr) {
		excess = len(arr)
	}
	for i := 0; i < excess; i++ {
		delete(e.entries, arr[i].key)
	}
}

func entityTypeFromKey(k string) EntityType {
	idx := strings.IndexByte(k, ':')
	if idx <= 0 {
		return EntityType("unknown")
	}
	switch k[:idx] {
	case string(TypeIP):
		return TypeIP
	case string(TypeJA4):
		return TypeJA4
	case string(TypeASN):
		return TypeASN
	case string(TypeUA):
		return TypeUA
	default:
		return EntityType("unknown")
	}
}
