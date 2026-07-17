package ratelimit

import (
	"net"
	"testing"
	"time"
)

// testConfig returns a Config with a cleanup interval long enough that the
// background cleanupLoop goroutine never fires during a test.
func testConfig() Config {
	cfg := DefaultConfig()
	cfg.CleanupInterval = time.Hour
	cfg.MaxAge = time.Hour
	return cfg
}

// W5: an "Unknown" (or empty) ASN must not be rate limited as a shared
// bucket -- every unresolved-ASN client would otherwise collide on one
// bucket that a single attacker can drain, blocking unrelated victims.
func TestAllowASN_UnknownASNIsNotRateLimited(t *testing.T) {
	cfg := testConfig()
	cfg.ASNBurst = 2
	cfg.ASNRate = 0 // no refill, so a shared bucket would stay drained forever
	l := NewLimiter(cfg)

	// Drain well past what a shared "Unknown" bucket's burst would allow.
	for i := 0; i < 10; i++ {
		if !l.AllowASN(UnknownASN) {
			t.Fatalf("call %d: AllowASN(%q) = false, want true (unresolved ASN must not be rate limited)", i, UnknownASN)
		}
	}

	// Empty string must behave the same way (pre-existing guarantee).
	for i := 0; i < 10; i++ {
		if !l.AllowASN("") {
			t.Fatalf("call %d: AllowASN(\"\") = false, want true", i)
		}
	}

	// No bucket should have been created for either sentinel value.
	_, asnCount := l.GetStats()
	if asnCount != 0 {
		t.Errorf("asnCount = %d, want 0 (Unknown/empty ASN must not allocate a bucket)", asnCount)
	}
}

// A real, resolved ASN must still be rate limited normally -- the fix must
// not disable ASN limiting altogether.
func TestAllowASN_KnownASNIsStillRateLimited(t *testing.T) {
	cfg := testConfig()
	cfg.ASNBurst = 2
	cfg.ASNRate = 0 // no refill within the test's lifetime
	l := NewLimiter(cfg)

	const asn = "AS12345"
	if !l.AllowASN(asn) {
		t.Fatalf("call 1: AllowASN(%q) = false, want true", asn)
	}
	if !l.AllowASN(asn) {
		t.Fatalf("call 2: AllowASN(%q) = false, want true", asn)
	}
	if l.AllowASN(asn) {
		t.Fatalf("call 3: AllowASN(%q) = true, want false (burst of 2 exhausted)", asn)
	}
}

// W5 regression: two different unresolved-ASN clients must not affect each
// other via a shared bucket. Before the fix both would collapse onto
// asnLimiters["Unknown"].
func TestAllowASN_UnknownASNDoesNotCollateralBlock(t *testing.T) {
	cfg := testConfig()
	cfg.ASNBurst = 1
	cfg.ASNRate = 0
	l := NewLimiter(cfg)

	// Simulate an attacker draining what would have been the shared bucket.
	for i := 0; i < 1000; i++ {
		l.AllowASN(UnknownASN)
	}

	// A victim with a different (also unresolved) ASN must still be allowed.
	if !l.AllowASN(UnknownASN) {
		t.Fatal("victim with Unknown ASN was blocked by unrelated attacker traffic sharing the same sentinel value")
	}
}

// W13: ipLimiters must not grow without bound; once the configured cap is
// reached, inserting a new key must evict rather than grow further.
func TestAllowIP_EntriesCappedAtMaxIPEntries(t *testing.T) {
	cfg := testConfig()
	cfg.MaxIPEntries = 3
	cfg.IPBurst = 10
	cfg.IPRate = 10
	l := NewLimiter(cfg)

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	for _, ipStr := range ips {
		l.AllowIP(net.ParseIP(ipStr))
	}

	ipCount, _ := l.GetStats()
	if ipCount > cfg.MaxIPEntries {
		t.Fatalf("ipCount = %d, want <= %d (MaxIPEntries cap)", ipCount, cfg.MaxIPEntries)
	}
	if ipCount != cfg.MaxIPEntries {
		t.Errorf("ipCount = %d, want exactly %d after inserting more than the cap", ipCount, cfg.MaxIPEntries)
	}
}

// W13: eviction must remove the least-recently-used entry, not an arbitrary
// one, so a still-active client isn't punished for an idle one's slot.
func TestAllowIP_EvictsLeastRecentlyUsed(t *testing.T) {
	cfg := testConfig()
	cfg.MaxIPEntries = 2
	cfg.IPBurst = 100
	cfg.IPRate = 100
	l := NewLimiter(cfg)

	oldIP := net.ParseIP("10.0.0.1")
	activeIP := net.ParseIP("10.0.0.2")

	l.AllowIP(oldIP)
	l.AllowIP(activeIP)

	// Keep activeIP fresh (advances its lastSeen) while oldIP goes idle.
	time.Sleep(2 * time.Millisecond)
	l.AllowIP(activeIP)

	// This insert should evict oldIP (the least recently used), not activeIP.
	newIP := net.ParseIP("10.0.0.3")
	l.AllowIP(newIP)

	l.mu.RLock()
	_, oldStillPresent := l.ipLimiters[oldIP.String()]
	_, activeStillPresent := l.ipLimiters[activeIP.String()]
	_, newPresent := l.ipLimiters[newIP.String()]
	l.mu.RUnlock()

	if oldStillPresent {
		t.Error("oldIP (least recently used) was not evicted")
	}
	if !activeStillPresent {
		t.Error("activeIP (recently used) was incorrectly evicted")
	}
	if !newPresent {
		t.Error("newIP was not inserted")
	}
}

// W13: same cap behavior for ASN limiters.
func TestAllowASN_EntriesCappedAtMaxASNEntries(t *testing.T) {
	cfg := testConfig()
	cfg.MaxASNEntries = 2
	cfg.ASNBurst = 10
	cfg.ASNRate = 10
	l := NewLimiter(cfg)

	for _, asn := range []string{"AS1", "AS2", "AS3", "AS4"} {
		l.AllowASN(asn)
	}

	_, asnCount := l.GetStats()
	if asnCount > cfg.MaxASNEntries {
		t.Fatalf("asnCount = %d, want <= %d (MaxASNEntries cap)", asnCount, cfg.MaxASNEntries)
	}
}

// W27: SetIPRate must update already-tracked IPs, not just the default used
// for IPs first seen after the call.
func TestSetIPRate_UpdatesExistingBuckets(t *testing.T) {
	cfg := testConfig()
	cfg.IPBurst = 1
	// NewLimiter treats IPRate==0 as "config unset" and substitutes the
	// full DefaultConfig(), so use a negligible non-zero rate to keep our
	// custom IPBurst/MaxIPEntries in effect while still not refilling
	// meaningfully within the test's sub-millisecond runtime.
	cfg.IPRate = 1e-6
	l := NewLimiter(cfg)

	ip := net.ParseIP("10.0.0.1")

	if !l.AllowIP(ip) {
		t.Fatal("call 1: expected the initial burst token to be allowed")
	}
	if l.AllowIP(ip) {
		t.Fatal("call 2: expected the bucket to be exhausted (negligible refill rate)")
	}

	// Raise the rate drastically; the existing bucket must pick this up
	// immediately rather than staying stuck at the old (zero) rate.
	l.SetIPRate(1e9)

	if !l.AllowIP(ip) {
		t.Fatal("call 3: SetIPRate did not take effect on the already-tracked IP's bucket")
	}
}

// W27: same behavior for SetASNRate.
func TestSetASNRate_UpdatesExistingBuckets(t *testing.T) {
	cfg := testConfig()
	cfg.ASNBurst = 1
	cfg.ASNRate = 0
	l := NewLimiter(cfg)

	const asn = "AS777"

	if !l.AllowASN(asn) {
		t.Fatal("call 1: expected the initial burst token to be allowed")
	}
	if l.AllowASN(asn) {
		t.Fatal("call 2: expected the bucket to be exhausted (rate=0, no refill)")
	}

	l.SetASNRate(1e9)

	if !l.AllowASN(asn) {
		t.Fatal("call 3: SetASNRate did not take effect on the already-tracked ASN's bucket")
	}
}
