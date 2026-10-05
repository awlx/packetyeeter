package analyzer

import (
	"net"
	"sync"
	"time"

	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/metrics"
)

// Trusted scrub evidence: the shared per-source state (RateLimiter,
// Reputation, AI windows) takes signals from every connected collector, so a
// decision judged on it can rest on evidence from any of them. Fan-out to
// other scrub nodes needs a decision judged on trusted scrub streams alone;
// these helpers keep that evidence apart, and trusted scrub streams are
// judged on it alone.

const (
	// scrubEvidenceTTL matches the rate limiter's idle bucket lifetime.
	scrubEvidenceTTL        = 10 * time.Minute
	scrubEvidenceMaxEntries = 200000
	// scrubEvidenceRefresh skips rewriting a fresh entry on every signal.
	scrubEvidenceRefresh = time.Second
)

// checkRateLimitFor applies the shared limiter to every signal and, for a
// trusted scrub stream, the trusted-only limiter as well. limited says the
// source should be blocked on cs; fanout says the trusted-only limiter
// tripped, so the block may go to every trusted scrub collector.
//
// On a trusted scrub stream limited comes from the trusted-only limiter
// alone. A trip of the shared limiter only (which any connected collector
// can drain, per IP or per ASN) is counted in
// scrub_shared_only_blocks_skipped_total{kind="rate_limit"} and penalises
// the shared reputation, and the signal goes on to normal analysis: an
// untrusted collector must not be able to exempt a source, or a whole ASN,
// from analysis on the scrub layer by keeping its shared bucket drained.
// Rate-limit metrics and blocked-source tracking record only trips that
// block. Other streams, and every stream with -scrub-client-names empty,
// are judged on the shared limiter as before.
func (a *Analyzer) checkRateLimitFor(cs *collectorStream, ip net.IP, asn string) (limited, fanout bool) {
	if cs == nil || !cs.isTrustedScrub() || a.ScrubRateLimiter == nil {
		return a.checkRateLimit(ip, asn), false
	}
	sharedLimited := a.RateLimiter != nil && !a.RateLimiter.Allow(ip, asn)
	if !a.ScrubRateLimiter.Allow(ip, asn) {
		a.recordRateLimitTrip(ip, asn)
		return true, true
	}
	if sharedLimited && !a.Config.DryRun {
		metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues("rate_limit").Inc()
		a.ReputationHelper.PenalizeIP(ip, 10.0, "Rate limit exceeded")
	}
	return false, false
}

// reputationVerdict returns the reputation score that decides a block of ip
// on cs and whether it crossed the threshold. fanout says the score is the
// trusted-only ScrubReputation, so the block may go to every trusted scrub
// collector. A trusted scrub stream is judged on ScrubReputation alone: the
// shared score, which any connected collector can raise (penalties) or lower
// (rewards, e.g. a browser JA4), neither blocks nor spares a source there;
// a shared-only crossing is counted in
// scrub_shared_only_blocks_skipped_total{kind="reputation"}. Other streams
// are judged on the shared score as before.
func (a *Analyzer) reputationVerdict(cs *collectorStream, ip net.IP) (score float64, exceeded, fanout bool) {
	if a.Reputation != nil {
		score = a.Reputation.GetScore(ip.String(), reputation.TypeIP)
	}
	if cs == nil || !cs.isTrustedScrub() {
		return score, score > a.Config.ReputationThreshold, false
	}
	sharedExceeded := score > a.Config.ReputationThreshold
	score = 0
	if a.ScrubReputation != nil {
		score = a.ScrubReputation.GetScore(ip.String(), reputation.TypeIP)
	}
	exceeded = score > a.Config.ReputationThreshold
	if sharedExceeded && !exceeded && !a.Config.DryRun {
		metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues("reputation").Inc()
	}
	return score, exceeded, exceeded
}

// penalizeRateLimited records a rate-limit trip in the shared reputation
// and, when it came from trusted scrub evidence, in ScrubReputation.
func (a *Analyzer) penalizeRateLimited(ip net.IP, trusted bool) {
	a.ReputationHelper.PenalizeIP(ip, 10.0, "Rate limit exceeded")
	if trusted && a.ScrubReputation != nil && ip != nil {
		a.ScrubReputation.Penalize(ip.String(), reputation.TypeIP, 10.0, "Rate limit exceeded (trusted scrub)")
	}
}

// evidenceSet remembers recently seen addresses, bounded in age and size.
// Inserts are O(1): a full set evicts the oldest of a small sample, and
// expired entries are dropped by purge, which cleanupTrackingMaps runs every
// few minutes, never on the insert path. A nil set is empty.
type evidenceSet struct {
	mu   sync.RWMutex
	seen map[string]time.Time
	ttl  time.Duration
	max  int
}

// evidenceEvictionSample bounds the entries an insert into a full set
// inspects, as in ratelimit's evictOldestLocked.
const evidenceEvictionSample = 8

func newEvidenceSet(ttl time.Duration, maxEntries int) *evidenceSet {
	return &evidenceSet{seen: make(map[string]time.Time), ttl: ttl, max: maxEntries}
}

func (e *evidenceSet) add(ip net.IP) {
	e.addAt(ip, time.Now())
}

func (e *evidenceSet) addAt(ip net.IP, now time.Time) {
	if e == nil || ip == nil {
		return
	}
	key := ip.String()
	e.mu.RLock()
	last, ok := e.seen[key]
	e.mu.RUnlock()
	if ok && now.Sub(last) < scrubEvidenceRefresh {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.seen[key]; !ok && len(e.seen) >= e.max {
		e.evictSampledLocked()
	}
	e.seen[key] = now
}

// evictSampledLocked drops the oldest of up to evidenceEvictionSample
// entries; Go's randomized map iteration makes them a pseudo-random sample.
func (e *evidenceSet) evictSampledLocked() {
	var oldest string
	var oldestAt time.Time
	n := 0
	for k, t := range e.seen {
		if n == 0 || t.Before(oldestAt) {
			oldest, oldestAt = k, t
		}
		if n++; n >= evidenceEvictionSample {
			break
		}
	}
	if n > 0 {
		delete(e.seen, oldest)
		metrics.ScrubEvidenceEvictions.Inc()
	}
}

// purge drops expired entries and returns how many remain.
func (e *evidenceSet) purge(now time.Time) int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, t := range e.seen {
		if now.Sub(t) >= e.ttl {
			delete(e.seen, k)
		}
	}
	return len(e.seen)
}

func (e *evidenceSet) len() int {
	if e == nil {
		return 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.seen)
}

func (e *evidenceSet) has(ip net.IP) bool {
	return e.hasAt(ip, time.Now())
}

func (e *evidenceSet) hasAt(ip net.IP, now time.Time) bool {
	if e == nil || ip == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	t, ok := e.seen[ip.String()]
	return ok && now.Sub(t) < e.ttl
}
