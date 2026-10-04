package analyzer

import (
	"net"
	"sync"
	"time"

	"PacketYeeter/pkg/analyzer/reputation"
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
	}
	return limited || fanout, fanout
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
// A nil set is empty.
type evidenceSet struct {
	mu   sync.RWMutex
	seen map[string]time.Time
	ttl  time.Duration
	max  int
}

func newEvidenceSet(ttl time.Duration, maxEntries int) *evidenceSet {
	return &evidenceSet{seen: make(map[string]time.Time), ttl: ttl, max: maxEntries}
}

func (e *evidenceSet) add(ip net.IP) {
	if e == nil || ip == nil {
		return
	}
	key := ip.String()
	now := time.Now()
	e.mu.RLock()
	last, ok := e.seen[key]
	e.mu.RUnlock()
	if ok && now.Sub(last) < scrubEvidenceRefresh {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.seen[key]; !ok && len(e.seen) >= e.max {
		e.evictLocked(now)
	}
	e.seen[key] = now
}

// evictLocked drops expired entries, or failing that a sampled oldest one.
func (e *evidenceSet) evictLocked(now time.Time) {
	for k, t := range e.seen {
		if now.Sub(t) >= e.ttl {
			delete(e.seen, k)
		}
	}
	if len(e.seen) < e.max {
		return
	}
	var oldest string
	var oldestAt time.Time
	n := 0
	for k, t := range e.seen {
		if n == 0 || t.Before(oldestAt) {
			oldest, oldestAt = k, t
		}
		if n++; n >= 8 {
			break
		}
	}
	delete(e.seen, oldest)
}

func (e *evidenceSet) has(ip net.IP) bool {
	if e == nil || ip == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	t, ok := e.seen[ip.String()]
	return ok && time.Since(t) < e.ttl
}
