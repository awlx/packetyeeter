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
// these helpers keep that evidence apart.

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
func (a *Analyzer) checkRateLimitFor(cs *collectorStream, ip net.IP, asn string) (limited, fanout bool) {
	limited = a.checkRateLimit(ip, asn)
	if cs != nil && cs.isTrustedScrub() && a.ScrubRateLimiter != nil {
		fanout = !a.ScrubRateLimiter.Allow(ip, asn)
		if fanout && !limited {
			// Count it like a shared trip: the source is blocked either way.
			a.recordRateLimitTrip(ip, asn)
		}
	}
	return limited || fanout, fanout
}

// skipSharedOnlyBlock reports whether a rate-limit or reputation block of a
// source on cs must be skipped: cs is a trusted scrub stream and only the
// shared state, which any connected collector feeds, crossed the threshold.
// Trusted scrub nodes block on trusted scrub evidence alone, so an untrusted
// collector cannot get a source blocked on them. Other streams block on the
// shared verdict as before; with -scrub-client-names empty no stream is
// trusted and nothing changes. kind labels the skip metric.
func (a *Analyzer) skipSharedOnlyBlock(cs *collectorStream, trustedVerdict bool, kind string) bool {
	if cs == nil || !cs.isTrustedScrub() || trustedVerdict {
		return false
	}
	metrics.ScrubSharedOnlyBlocksSkipped.WithLabelValues(kind).Inc()
	return true
}

// penalizeRateLimited records a rate-limit trip in the shared reputation
// and, when it came from trusted scrub evidence, in ScrubReputation.
func (a *Analyzer) penalizeRateLimited(ip net.IP, trusted bool) {
	a.ReputationHelper.PenalizeIP(ip, 10.0, "Rate limit exceeded")
	if trusted && a.ScrubReputation != nil && ip != nil {
		a.ScrubReputation.Penalize(ip.String(), reputation.TypeIP, 10.0, "Rate limit exceeded (trusted scrub)")
	}
}

// scrubReputationExceeded reports whether a reputation block decided from
// cs's signal may fan out: cs is a trusted scrub stream and trusted scrub
// evidence alone puts ip over the threshold.
func (a *Analyzer) scrubReputationExceeded(cs *collectorStream, ip net.IP) bool {
	if cs == nil || !cs.isTrustedScrub() || a.ScrubReputation == nil || ip == nil {
		return false
	}
	return a.ScrubReputation.GetScore(ip.String(), reputation.TypeIP) > a.Config.ReputationThreshold
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
