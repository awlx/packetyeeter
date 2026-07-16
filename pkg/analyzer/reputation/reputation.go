package reputation

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

	// reputationShardCount controls how many independent lock+map shards
	// back the engine. Every Penalize/Reward/RecordSignal call previously
	// took one engine-wide mutex, which fully serialized all 16 AI-engine
	// worker goroutines on every single detection signal (confirmed live:
	// queue permanently full, ~50% of signals dropped, CPU far below
	// capacity - classic lock-contention starvation, not CPU exhaustion).
	// Sharding by a hash of the entity key (IP/ASN/JA4H) spreads that
	// contention across many independent locks so concurrent workers only
	// collide when they happen to hash to the same shard.
	reputationShardCount = 32
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

// repShard is one independently-locked partition of the reputation store.
// entries and asnStats are both keyed/sharded by the same raw entity value
// (e.g. the bare ASN string, ignoring the "asn:" type prefix used inside
// entries), so a single ASN's Entry and its asnStats always live behind the
// same lock and can be updated together without acquiring a second shard.
type repShard struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	asnStats map[string]*asnStats
}

type Engine struct {
	shards [reputationShardCount]*repShard

	// Score caps and the ban threshold are read on every Penalize/Reward
	// call across all shard workers but change rarely (only via the Set*
	// methods below, invoked once during startup config), so they're held
	// atomically rather than behind a shared mutex - a shared config lock
	// here would reintroduce exactly the kind of global contention that
	// sharding the entries/asnStats maps is meant to eliminate.
	asnScoreCapBits  atomic.Uint64
	ipScoreCapBits   atomic.Uint64
	ja4ScoreCapBits  atomic.Uint64
	banThresholdBits atomic.Uint64

	decayTick   *time.Ticker
	decayFactor float64 // Multiplier per tick (e.g., 0.95); immutable after New
	stop        chan struct{}

	maxEntries       atomic.Int64
	maxEntryAgeNanos atomic.Int64
	maxASNHosts      atomic.Int64
}

// New creates a reputation engine. Each decay tick multiplies scores by
// decayFactor; for example, a 5 minute interval with factor 0.95 has a score
// half-life of about 67.6 minutes.
func New(decayInterval time.Duration, decayFactor float64, banThreshold float64) *Engine {
	e := &Engine{
		decayTick:   time.NewTicker(decayInterval),
		decayFactor: decayFactor,
		stop:        make(chan struct{}),
	}
	for i := range e.shards {
		e.shards[i] = &repShard{
			entries:  make(map[string]*Entry),
			asnStats: make(map[string]*asnStats),
		}
	}
	// All per-type score caps default to +Inf (uncapped); operators lower them
	// via SetIPScoreCap/SetJA4ScoreCap/SetASNScoreCap. Leaving a cap at the
	// zero value would clamp every penalty of that type back to 0 in
	// penalizeLocked, silently turning per-IP/JA4 reputation into a no-op.
	e.ipScoreCapBits.Store(math.Float64bits(math.Inf(1)))
	e.ja4ScoreCapBits.Store(math.Float64bits(math.Inf(1)))
	e.asnScoreCapBits.Store(math.Float64bits(math.Inf(1)))
	e.banThresholdBits.Store(math.Float64bits(banThreshold))
	e.maxEntries.Store(defaultMaxEntries)
	e.maxEntryAgeNanos.Store(int64(defaultMaxEntryAge))
	e.maxASNHosts.Store(defaultMaxASNHosts)
	return e
}

// shardFor returns the shard owning key. Callers pass the bare entity value
// (IP, ASN, or JA4H fingerprint) - never the "type:key" store key - so that
// an ASN's entries map entry and its asnStats always land in the same shard.
func (e *Engine) shardFor(key string) *repShard {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return e.shards[h.Sum64()%reputationShardCount]
}

// deleteEntryLocked removes a reputation entry and, when it is an ASN's
// Entry, also drops the parallel sh.asnStats bookkeeping (the Seen/Offenders
// IP sets) for that ASN. Without this, asnStats entries outlive the
// reputation Entry that represents them: decay()/pruneIfNeededLocked only
// ever deleted from sh.entries, so every ASN ever observed retained up to
// ~2*maxASNHosts IP strings indefinitely, even long after its score decayed
// away and its Entry was reclaimed. An ASN's Entry and its asnStats always
// share a shard (see shardFor), so this stays within the caller's lock.
func (e *Engine) deleteEntryLocked(sh *repShard, storeKey string) {
	delete(sh.entries, storeKey)
	if asn, ok := strings.CutPrefix(storeKey, string(TypeASN)+":"); ok {
		delete(sh.asnStats, asn)
	}
}

func (e *Engine) getIPScoreCap() float64   { return math.Float64frombits(e.ipScoreCapBits.Load()) }
func (e *Engine) getJA4ScoreCap() float64  { return math.Float64frombits(e.ja4ScoreCapBits.Load()) }
func (e *Engine) getASNScoreCap() float64  { return math.Float64frombits(e.asnScoreCapBits.Load()) }
func (e *Engine) getBanThreshold() float64 { return math.Float64frombits(e.banThresholdBits.Load()) }

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
	e.asnScoreCapBits.Store(math.Float64bits(cap))
	prefix := string(TypeASN) + ":"
	for _, sh := range e.shards {
		sh.mu.Lock()
		for k, entry := range sh.entries {
			if strings.HasPrefix(k, prefix) && entry.Score > cap {
				entry.Score = cap
				setReputationScore(TypeASN, k[len(prefix):], entry.Score)
			}
		}
		for asn := range sh.asnStats {
			if _, exists := sh.entries[string(TypeASN)+":"+asn]; !exists {
				delete(sh.asnStats, asn)
			}
		}
		sh.mu.Unlock()
	}
}

func (e *Engine) SetIPScoreCap(cap float64) {
	e.ipScoreCapBits.Store(math.Float64bits(cap))
	prefix := string(TypeIP) + ":"
	for _, sh := range e.shards {
		sh.mu.Lock()
		for k, entry := range sh.entries {
			if strings.HasPrefix(k, prefix) && entry.Score > cap {
				entry.Score = cap
				setReputationScore(TypeIP, k[len(prefix):], entry.Score)
			}
		}
		sh.mu.Unlock()
	}
}

func (e *Engine) SetJA4ScoreCap(cap float64) {
	e.ja4ScoreCapBits.Store(math.Float64bits(cap))
	prefix := string(TypeJA4) + ":"
	for _, sh := range e.shards {
		sh.mu.Lock()
		for k, entry := range sh.entries {
			if strings.HasPrefix(k, prefix) && entry.Score > cap {
				entry.Score = cap
				setReputationScore(TypeJA4, k[len(prefix):], entry.Score)
			}
		}
		sh.mu.Unlock()
	}
}

func (e *Engine) SetMaxEntries(max int) {
	if max <= 0 {
		return
	}
	e.maxEntries.Store(int64(max))
}

func (e *Engine) SetMaxEntryAge(age time.Duration) {
	if age <= 0 {
		return
	}
	e.maxEntryAgeNanos.Store(int64(age))
}

func (e *Engine) SetMaxASNHosts(max int) {
	if max <= 0 {
		return
	}
	e.maxASNHosts.Store(int64(max))
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
	sh := e.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return e.penalizeLocked(sh, key, keyType, weight, reason)
}

func (e *Engine) penalizeLocked(sh *repShard, key string, keyType EntityType, weight float64, reason string) float64 {
	storeKey := string(keyType) + ":" + key
	entry, exists := sh.entries[storeKey]

	if !exists {
		entry = &Entry{
			FirstSeen: time.Now(),
		}
		sh.entries[storeKey] = entry
	}

	entry.Score += weight
	switch keyType {
	case TypeIP:
		if cap := e.getIPScoreCap(); entry.Score > cap {
			entry.Score = cap
		}
	case TypeJA4:
		if cap := e.getJA4ScoreCap(); entry.Score > cap {
			entry.Score = cap
		}
	}
	entry.LastSeen = time.Now()
	entry.Offenses++

	banThreshold := e.getBanThreshold()
	if entry.Score >= banThreshold && (entry.Score-weight) < banThreshold {
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
	// disabled - logrus.WithFields() always allocates/copies the map
	// eagerly even if the resulting Debug() call is a no-op. This runs
	// under sh.mu for every Penalize call (up to several per signal across
	// all AI-engine workers), so the allocation cost is paid while holding
	// the shard lock.
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(logrus.Fields{
			"key":    key,
			"type":   keyType,
			"added":  weight,
			"total":  entry.Score,
			"reason": reason,
		}).Debug("Reputation Penalized")
	}

	e.pruneIfNeededLocked(sh)

	return entry.Score
}

// ObserveIP tracks a unique IP seen for an ASN (used for normalization)
func (e *Engine) ObserveIP(asn string, ip string) {
	if asn == "" || ip == "" {
		return
	}
	sh := e.shardFor(asn)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	stats := e.getASNStatsLocked(sh, asn)
	stats.Seen[ip] = struct{}{}
	e.boundASNStatsLocked(stats)
}

// PenalizeASN scales the ASN penalty by the ratio of offending IPs to total IPs seen for that ASN
func (e *Engine) PenalizeASN(asn string, ip string, baseWeight float64, reason string) float64 {
	if asn == "" {
		return 0
	}
	sh := e.shardFor(asn)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	stats := e.getASNStatsLocked(sh, asn)
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
	return e.penalizeASNLocked(sh, asn, weight, fmt.Sprintf("%s (ratio=%.4f offenders=%d total=%d)", reason, ratio, offenders, total))
}

// RecordSignal applies the IP, ASN, and JA4H reputation penalties for a
// single detection signal, instead of the equivalent sequence of
// Penalize/ObserveIP/PenalizeASN/Penalize calls it replaces. Under the AI
// detection engine's per-worker signal processing (see
// aidetection.Engine.processSignal), every signal calls into reputation
// tracking, so this batches the up-to-three independent lookups this method
// needs into one call.
//
// Each of the IP, ASN, and JA4H updates is scoped to its own shard lock
// (via shardFor), acquired and released independently rather than under one
// combined lock: because IP/ASN/JA4H are unrelated keys that hash to
// different shards, holding a single lock across all three would mean
// either a lock per call that most callers don't need, or collapsing back
// to one engine-wide mutex - the exact contention bottleneck sharding
// exists to remove. No caller depends on the three updates being visible
// atomically together (the pre-existing individual Penalize/ObserveIP/
// PenalizeASN call sequence never offered that guarantee either - each was
// already a separate lock acquisition), so this preserves the original
// score-calculation semantics while allowing concurrent signals for
// different entities to make progress in parallel.
//
// ip and asnWeight are ignored (no-op) when the respective key ("" for ip
// or asn) is empty, matching the guards in the individual methods.
func (e *Engine) RecordSignal(ip string, ipWeight float64, asn string, asnWeight float64, ja4h string, ja4Weight float64, reason string) (ipScore, asnScore float64) {
	if ip != "" {
		sh := e.shardFor(ip)
		sh.mu.Lock()
		ipScore = e.penalizeLocked(sh, ip, TypeIP, ipWeight, reason)
		sh.mu.Unlock()
	}

	if asn != "" {
		sh := e.shardFor(asn)
		sh.mu.Lock()
		stats := e.getASNStatsLocked(sh, asn)
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
		asnScore = e.penalizeASNLocked(sh, asn, weight, fmt.Sprintf("%s (ratio=%.4f offenders=%d total=%d)", reason, ratio, offenders, total))
		sh.mu.Unlock()
	}

	if ja4h != "" {
		sh := e.shardFor(ja4h)
		sh.mu.Lock()
		e.penalizeLocked(sh, ja4h, TypeJA4, ja4Weight, reason)
		sh.mu.Unlock()
	}

	return ipScore, asnScore
}

// RewardASN decreases the ASN score based on good traffic ratio
func (e *Engine) RewardIP(ip string, baseWeight float64, reason string) float64 {
	if ip == "" {
		return 0
	}
	sh := e.shardFor(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return e.rewardLocked(sh, ip, TypeIP, baseWeight, reason)
}

func (e *Engine) RewardJA4(ja4 string, baseWeight float64, reason string) float64 {
	if ja4 == "" {
		return 0
	}
	sh := e.shardFor(ja4)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return e.rewardLocked(sh, ja4, TypeJA4, baseWeight, reason)
}

func (e *Engine) rewardLocked(sh *repShard, key string, keyType EntityType, weight float64, reason string) float64 {
	storeKey := string(keyType) + ":" + key
	entry, exists := sh.entries[storeKey]
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
	sh := e.shardFor(asn)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	stats := e.getASNStatsLocked(sh, asn)
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
	return e.rewardASNLocked(sh, asn, weight, fmt.Sprintf("%s (ratio=%.4f offenders=%d total=%d)", reason, ratio, offenders, total))
}

func (e *Engine) penalizeASNLocked(sh *repShard, asn string, weight float64, reason string) float64 {
	storeKey := string(TypeASN) + ":" + asn
	entry, exists := sh.entries[storeKey]
	if !exists {
		entry = &Entry{FirstSeen: time.Now()}
		sh.entries[storeKey] = entry
	}
	// Dampen repeated offenses
	dampen := 1.0 / math.Sqrt(float64(entry.Offenses)+1)
	weight = weight * dampen
	entry.Score += weight
	if cap := e.getASNScoreCap(); entry.Score > cap {
		entry.Score = cap
	}
	entry.LastSeen = time.Now()
	entry.Offenses++

	banThreshold := e.getBanThreshold()
	if entry.Score >= banThreshold && (entry.Score-weight) < banThreshold {
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

func (e *Engine) rewardASNLocked(sh *repShard, asn string, weight float64, reason string) float64 {
	storeKey := string(TypeASN) + ":" + asn
	entry, exists := sh.entries[storeKey]
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
	sh := e.shardFor(asn)
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	if stats, ok := sh.asnStats[asn]; ok {
		return len(stats.Seen), len(stats.Offenders)
	}
	return 0, 0
}

func (e *Engine) getASNStatsLocked(sh *repShard, asn string) *asnStats {
	stats, ok := sh.asnStats[asn]
	if !ok {
		stats = &asnStats{Seen: make(map[string]struct{}), Offenders: make(map[string]struct{})}
		sh.asnStats[asn] = stats
	}
	return stats
}

func (e *Engine) boundASNStatsLocked(stats *asnStats) {
	maxASNHosts := int(e.maxASNHosts.Load())
	if maxASNHosts <= 0 {
		return
	}
	if len(stats.Seen) > maxASNHosts {
		excess := len(stats.Seen) - maxASNHosts
		i := 0
		for k := range stats.Seen {
			delete(stats.Seen, k)
			i++
			if i >= excess {
				break
			}
		}
	}
	if len(stats.Offenders) > maxASNHosts {
		excess := len(stats.Offenders) - maxASNHosts
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
	sh := e.shardFor(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	storeKey := string(keyType) + ":" + key
	if entry, ok := sh.entries[storeKey]; ok {
		return entry.Score >= e.getBanThreshold()
	}
	return false
}

// GetScore returns the raw score
func (e *Engine) GetScore(key string, keyType EntityType) float64 {
	sh := e.shardFor(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	storeKey := string(keyType) + ":" + key
	if entry, ok := sh.entries[storeKey]; ok {
		return entry.Score
	}
	return 0
}

// GetEntry returns the full entry for inspection. key is the bare entity
// value (as originally stored via Penalize/RecordSignal/etc.), which lets
// us jump straight to its shard instead of scanning every entry.
func (e *Engine) GetEntry(key string) *Entry {
	sh := e.shardFor(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	suffix := ":" + key
	for k, v := range sh.entries {
		if strings.HasSuffix(k, suffix) {
			return v
		}
	}
	return nil
}

// GetBadEntries returns a map of bad actors (Type:Key format)
func (e *Engine) GetBadEntries() map[string]float64 {
	banThreshold := e.getBanThreshold()
	bad := make(map[string]float64)
	for _, sh := range e.shards {
		sh.mu.RLock()
		for k, v := range sh.entries {
			if v.Score >= banThreshold {
				bad[k] = v.Score
			}
		}
		sh.mu.RUnlock()
	}
	return bad
}

// GetAllEntries returns a copy of all reputation entries
func (e *Engine) GetAllEntries() map[string]*Entry {
	result := make(map[string]*Entry)
	for _, sh := range e.shards {
		sh.mu.RLock()
		for k, v := range sh.entries {
			// Deep copy entry to avoid race conditions if caller modifies it
			eVal := *v
			result[k] = &eVal
		}
		sh.mu.RUnlock()
	}
	return result
}

func (e *Engine) decay() {
	now := time.Now()
	maxEntryAge := time.Duration(e.maxEntryAgeNanos.Load())
	counts := map[EntityType]int{}

	for _, sh := range e.shards {
		sh.mu.Lock()
		for k, entry := range sh.entries {
			entry.Score *= e.decayFactor

			if maxEntryAge > 0 && now.Sub(entry.LastSeen) > maxEntryAge {
				e.deleteEntryLocked(sh, k)
				continue
			}
			if entry.Score < 0.1 {
				// Cleanup low scores to save memory
				e.deleteEntryLocked(sh, k)
				continue
			}

			t := entityTypeFromKey(k)
			counts[t]++
		}

		e.pruneIfNeededLocked(sh)
		sh.mu.Unlock()
	}

	for t, c := range counts {
		ReputationEntryCounts.WithLabelValues(string(t)).Set(float64(c))
	}
}

// pruneIfNeededLocked bounds a single shard's entry count to roughly
// maxEntries/reputationShardCount (minimum 1). This distributes the
// previously-global maxEntries budget evenly across shards rather than
// maintaining one exact global LRU cap; the total bound across all shards
// remains approximately maxEntries, and evicting the oldest entries within
// a shard (instead of coordinating an eviction across all shards under one
// lock) is what lets this run without reintroducing global contention.
func (e *Engine) pruneIfNeededLocked(sh *repShard) {
	maxEntries := e.maxEntries.Load()
	if maxEntries <= 0 {
		return
	}
	perShardBudget := maxEntries / reputationShardCount
	if perShardBudget < 1 {
		perShardBudget = 1
	}
	if int64(len(sh.entries)) <= perShardBudget {
		return
	}

	// Evict a batch (down to ~90% of budget) instead of exactly the excess:
	// pruning to the budget means the very next new-key Penalize is over
	// budget again, so a distinct-IP flood pays this full-shard sort on
	// every signal (~1.5ms and ~365KB per insert at the default budget)
	// while holding the shard write lock. Batching amortizes the sort to
	// once per ~budget/10 inserts.
	excess := int64(len(sh.entries)) - perShardBudget + perShardBudget/10
	type kv struct {
		key      string
		lastSeen time.Time
	}
	arr := make([]kv, 0, len(sh.entries))
	for k, v := range sh.entries {
		arr = append(arr, kv{key: k, lastSeen: v.LastSeen})
	}
	sort.Slice(arr, func(i, j int) bool {
		return arr[i].lastSeen.Before(arr[j].lastSeen)
	})
	if excess > int64(len(arr)) {
		excess = int64(len(arr))
	}
	for i := int64(0); i < excess; i++ {
		e.deleteEntryLocked(sh, arr[i].key)
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
