package threatintel

import (
	"net"
	"testing"
	"time"
)

// A rate-limited (or otherwise failed) lookup must not populate the
// enrichment cache: the all-default entry would read as "clean" for
// enrichmentTTL and suppress every retry, silently degrading enrichment
// exactly when lookup volume is highest.
func TestRateLimitedLookupDoesNotPoisonCache(t *testing.T) {
	ti := NewThreatIntelligence()
	ip := net.ParseIP("192.0.2.50")

	// Force the Shodan client's min-interval rate limit so Lookup fails
	// without touching the network.
	ti.shodan.mu.Lock()
	ti.shodan.lastRequest = time.Now()
	ti.shodan.mu.Unlock()

	ti.performEnrichment(ip)

	if info := ti.GetEnrichedInfo(ip); info != nil {
		t.Fatalf("rate-limited lookup cached %+v; want no cache entry so a later signal retries", info)
	}
}
