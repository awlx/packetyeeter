package threatintel

import (
	"net"
	"testing"
	"time"

	"PacketYeeter/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// newTestThreatIntelligence builds a ThreatIntelligence with the given
// enrichment queue capacity but does NOT start any workers or a real
// Shodan client, so tests can exercise EnrichIP's queueing/dedup logic in
// isolation without making outbound network calls.
func newTestThreatIntelligence(queueCap int) *ThreatIntelligence {
	return &ThreatIntelligence{
		enrichmentCache: make(map[string]*EnrichedIPInfo),
		enrichmentTTL:   12 * time.Hour,
		enrichQueue:     make(chan net.IP, queueCap),
		inFlight:        make(map[string]struct{}),
	}
}

func TestEnrichIPQueuesAndTracksInFlight(t *testing.T) {
	ti := newTestThreatIntelligence(4)
	ip := net.ParseIP("203.0.113.5")

	ti.EnrichIP(ip)

	if got := len(ti.enrichQueue); got != 1 {
		t.Fatalf("expected 1 queued enrichment, got %d", got)
	}
	ti.inFlightMu.Lock()
	_, tracked := ti.inFlight[ip.String()]
	ti.inFlightMu.Unlock()
	if !tracked {
		t.Fatal("expected IP to be tracked as in-flight after queueing")
	}
}

func TestEnrichIPDedupSkipsSecondCallWhileInFlight(t *testing.T) {
	ti := newTestThreatIntelligence(4)
	ip := net.ParseIP("203.0.113.6")

	ti.EnrichIP(ip)
	ti.EnrichIP(ip) // duplicate while first is still "in flight"

	if got := len(ti.enrichQueue); got != 1 {
		t.Fatalf("expected duplicate request to be deduped, queue has %d items", got)
	}
}

func TestEnrichIPCacheHitSkipsQueue(t *testing.T) {
	ti := newTestThreatIntelligence(4)
	ip := net.ParseIP("203.0.113.7")

	ti.mu.Lock()
	ti.enrichmentCache[ip.String()] = &EnrichedIPInfo{
		IP:          ip.String(),
		LastUpdated: time.Now(),
	}
	ti.mu.Unlock()

	ti.EnrichIP(ip)

	if got := len(ti.enrichQueue); got != 0 {
		t.Fatalf("expected fresh cache entry to skip queueing, queue has %d items", got)
	}
}

func TestEnrichIPQueueFullDropsAndClearsInFlight(t *testing.T) {
	ti := newTestThreatIntelligence(1)

	// Fill the single queue slot with a different IP so it never gets
	// drained (no workers running in this test).
	filler := net.ParseIP("198.51.100.1")
	ti.EnrichIP(filler)
	if got := len(ti.enrichQueue); got != 1 {
		t.Fatalf("setup: expected filler to occupy the queue, got %d", got)
	}

	dropsBefore := testutil.ToFloat64(metrics.ThreatIntelEnrichQueueDrops)

	overflow := net.ParseIP("198.51.100.2")
	ti.EnrichIP(overflow)

	dropsAfter := testutil.ToFloat64(metrics.ThreatIntelEnrichQueueDrops)
	if dropsAfter != dropsBefore+1 {
		t.Fatalf("expected drop counter to increment by 1, went from %v to %v", dropsBefore, dropsAfter)
	}

	// The dropped IP must not be left dangling in the in-flight set,
	// otherwise a later signal for it could be silently deduped forever.
	ti.inFlightMu.Lock()
	_, stillTracked := ti.inFlight[overflow.String()]
	ti.inFlightMu.Unlock()
	if stillTracked {
		t.Fatal("dropped enrichment must not remain marked in-flight")
	}
}

func TestEnrichWorkerClearsInFlightAfterProcessing(t *testing.T) {
	ti := newTestThreatIntelligence(4)
	ti.shodan = NewShodanInternetDB(time.Hour)

	ip := net.ParseIP("203.0.113.8")
	ti.EnrichIP(ip)

	done := make(chan struct{})
	go func() {
		ti.enrichWorker()
		close(done)
	}()

	// enrichWorker ranges over the channel; close it once the single
	// queued job has had time to be picked up so the goroutine exits.
	deadline := time.Now().Add(5 * time.Second)
	for {
		ti.inFlightMu.Lock()
		_, tracked := ti.inFlight[ip.String()]
		ti.inFlightMu.Unlock()
		if !tracked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for enrichWorker to clear in-flight marker")
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(ti.enrichQueue)
	<-done
}
