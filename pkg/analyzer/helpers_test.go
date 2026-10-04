package analyzer

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"PacketYeeter/pkg/analyzer/reputation"
)

// trackBlocked is called from per-collector gRPC stream handler goroutines, so
// it must be safe for concurrent use. Run with -race: this fails with
// "concurrent map writes" when blockedIPs/blockedASNs are unsynchronized.
func TestTrackBlockedConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ip := net.ParseIP(fmt.Sprintf("192.0.2.%d", (g*200+i)%256))
				trackBlocked(ip, fmt.Sprintf("AS%d", g))
			}
		}(g)
	}
	wg.Wait()
}

func resetBlockedTracking(t *testing.T, lastSweep time.Time) {
	t.Helper()
	blockedMu.Lock()
	blockedIPs = make(map[string]time.Time)
	blockedASNs = make(map[string]time.Time)
	blockedLastSweep = lastSweep
	blockedMu.Unlock()
	t.Cleanup(func() {
		blockedMu.Lock()
		blockedIPs = make(map[string]time.Time)
		blockedASNs = make(map[string]time.Time)
		blockedLastSweep = time.Time{}
		blockedMu.Unlock()
	})
}

func TestTrackBlockedSweepIsThrottled(t *testing.T) {
	// A future last sweep keeps a slow -race run from crossing the interval.
	resetBlockedTracking(t, time.Now().Add(time.Hour))
	stale := time.Now().Add(-2 * blockedWindow)
	blockedMu.Lock()
	blockedIPs["198.51.100.1"] = stale
	blockedASNs["AS64501"] = stale
	blockedMu.Unlock()

	trackBlocked(net.ParseIP("198.51.100.2"), "AS64500")
	blockedMu.Lock()
	_, ipKept := blockedIPs["198.51.100.1"]
	_, asnKept := blockedASNs["AS64501"]
	blockedMu.Unlock()
	if !ipKept || !asnKept {
		t.Fatal("expired entries swept again within blockedSweepInterval")
	}

	blockedMu.Lock()
	blockedLastSweep = time.Now().Add(-blockedSweepInterval)
	blockedMu.Unlock()
	trackBlocked(net.ParseIP("198.51.100.3"), "AS64500")
	blockedMu.Lock()
	defer blockedMu.Unlock()
	if _, ok := blockedIPs["198.51.100.1"]; ok {
		t.Fatal("expired IP not swept once the interval elapsed")
	}
	if _, ok := blockedASNs["AS64501"]; ok {
		t.Fatal("expired ASN not swept once the interval elapsed")
	}
	for _, ip := range []string{"198.51.100.2", "198.51.100.3"} {
		if _, ok := blockedIPs[ip]; !ok {
			t.Fatalf("live IP %s was swept", ip)
		}
	}
}

func TestTrackBlockedCapped(t *testing.T) {
	resetBlockedTracking(t, time.Now())
	old := time.Now().Add(-time.Second)
	blockedMu.Lock()
	for i := 0; i < maxTrackedBlocked; i++ {
		blockedIPs[fmt.Sprintf("k%d", i)] = old
	}
	blockedMu.Unlock()

	trackBlocked(net.ParseIP("203.0.113.9"), "")
	blockedMu.Lock()
	_, added := blockedIPs["203.0.113.9"]
	size := len(blockedIPs)
	blockedMu.Unlock()
	if added || size != maxTrackedBlocked {
		t.Fatalf("cap not enforced: added=%v size=%d cap=%d", added, size, maxTrackedBlocked)
	}

	// A tracked key at the cap is still refreshed.
	blockedMu.Lock()
	delete(blockedIPs, "k0")
	blockedIPs["203.0.113.10"] = old
	blockedMu.Unlock()
	trackBlocked(net.ParseIP("203.0.113.10"), "")
	blockedMu.Lock()
	defer blockedMu.Unlock()
	if !blockedIPs["203.0.113.10"].After(old) {
		t.Fatal("existing key not refreshed at the cap")
	}
}

// markBlocked reserves a local block of ip for a throwaway collector.
func (a *Analyzer) markBlocked(ip net.IP) {
	a.reserveBlock(ip, scopeLocal, []*collectorStream{{}}, time.Now())
}

// liveReservation returns ip's block reservation if it is within the TTL.
func liveReservation(a *Analyzer, ip net.IP) *blockReservation {
	a.recentBlocksMu.Lock()
	defer a.recentBlocksMu.Unlock()
	if r, ok := a.recentBlocks[ip.String()]; ok && time.Since(r.at) < recentBlockTTL {
		return r
	}
	return nil
}

func TestRecentBlocksTTLIndependentOfSweep(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.cancel)
	now := time.Now()
	expired, live, stale := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.3")
	a.recentBlocks[expired.String()] = &blockReservation{at: now.Add(-recentBlockTTL - time.Second), scopes: scopeLocal}
	a.recentBlocks[live.String()] = &blockReservation{at: now.Add(-recentBlockTTL + 5*time.Second), scopes: scopeLocal}
	a.recentBlocks[stale.String()] = &blockReservation{at: now.Add(-3 * recentBlockTTL), scopes: scopeLocal}
	// Future, so a slow -race run cannot cross the sweep interval.
	a.recentBlocksSwept = now.Add(time.Hour)

	a.markBlocked(net.ParseIP("192.0.2.4"))
	if _, ok := a.recentBlocks[stale.String()]; !ok {
		t.Fatal("sweep ran again within recentBlocksSweepInterval")
	}
	// Past-TTL entries the sweep has not reached yet must still read as expired.
	if liveReservation(a, expired) != nil || liveReservation(a, stale) != nil {
		t.Fatal("entry past TTL treated as recently blocked before sweep")
	}
	if liveReservation(a, live) == nil {
		t.Fatal("entry within TTL not treated as recently blocked")
	}

	a.recentBlocksSwept = now.Add(-recentBlocksSweepInterval)
	a.markBlocked(net.ParseIP("192.0.2.5"))
	if _, ok := a.recentBlocks[stale.String()]; ok {
		t.Fatal("stale entry not swept once the interval elapsed")
	}
	if _, ok := a.recentBlocks[expired.String()]; !ok {
		t.Fatal("entry within 2x TTL swept early; sweep cutoff changed")
	}
}

func TestCloseIdempotent(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	rep := reputation.New(time.Hour, 0.95, 100)
	rep.Start()
	a.Reputation = rep
	a.Close()
	a.Close()
}
