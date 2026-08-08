package ratelimit

import (
	"net"
	"testing"
	"time"
)

func ptrFloat(f float64) *float64 { return &f }

// Sampled eviction must keep the map bounded at its cap even for maps far larger
// than evictionSampleSize, which is the adversarial high-cardinality case the
// O(n) scan handled too slowly.
func TestAllowIP_SampledEvictionKeepsMapBounded(t *testing.T) {
	cfg := testConfig()
	cfg.MaxIPEntries = 20
	cfg.IPBurst = 100
	cfg.IPRate = 100
	l := NewLimiter(cfg)

	for i := 0; i < 500; i++ {
		l.AllowIP(net.IPv4(10, 0, byte(i>>8), byte(i)))
		ipCount, _ := l.GetStats()
		if ipCount > cfg.MaxIPEntries {
			t.Fatalf("map exceeded cap during inserts: %d > %d", ipCount, cfg.MaxIPEntries)
		}
	}

	ipCount, _ := l.GetStats()
	if ipCount != cfg.MaxIPEntries {
		t.Fatalf("final ipCount = %d, want exactly %d", ipCount, cfg.MaxIPEntries)
	}
}

// setRate must credit accrual for the elapsed interval at the OLD rate before
// installing the new rate, then clamp to the new capacity.
func TestSetRate_CreditsOldRateBeforeSwitch(t *testing.T) {
	tb := &TokenBucket{
		capacity: 10,
		tokens:   0,
		rate:     2, // old rate: 2 tokens/sec
		lastSeen: time.Now().Add(-3 * time.Second),
	}

	tb.setRate(50, 10) // new rate 50, same capacity

	tb.mu.Lock()
	tokens := tb.tokens
	rate := tb.rate
	capacity := tb.capacity
	tb.mu.Unlock()

	// 3s elapsed * old rate 2 = 6 tokens accrued, clamped to cap 10 -> 6.
	if tokens < 5.5 || tokens > 6.5 {
		t.Fatalf("tokens = %v, want ~6 (3s at old rate 2)", tokens)
	}
	if rate != 50 {
		t.Fatalf("rate = %v, want 50", rate)
	}
	if capacity != 10 {
		t.Fatalf("capacity = %v, want 10", capacity)
	}
}

// When the new capacity is smaller than the tokens accrued at the old rate, the
// held tokens must be clamped down to the new capacity.
func TestSetRate_ClampsToNewSmallerCapacity(t *testing.T) {
	tb := &TokenBucket{
		capacity: 100,
		tokens:   0,
		rate:     10,
		lastSeen: time.Now().Add(-5 * time.Second),
	}

	tb.setRate(1, 3) // accrues 5*10=50 at old rate, then clamp to new cap 3

	tb.mu.Lock()
	tokens := tb.tokens
	tb.mu.Unlock()

	if tokens != 3 {
		t.Fatalf("tokens = %v, want 3 (clamped to new capacity)", tokens)
	}
}

// An explicit exact rate of 0 must be preserved, not defaulted to 100/1000.
func TestNewLimiter_ExplicitZeroRatePreserved(t *testing.T) {
	cfg := testConfig()
	cfg.IPRateExact = ptrFloat(0)
	cfg.ASNRateExact = ptrFloat(0)
	l := NewLimiter(cfg)

	if l.ipRate != 0 {
		t.Fatalf("ipRate = %v, want 0 (explicit exact zero preserved)", l.ipRate)
	}
	if l.asnRate != 0 {
		t.Fatalf("asnRate = %v, want 0 (explicit exact zero preserved)", l.asnRate)
	}
}

// Backward compatibility: a plain IPRate/ASNRate of 0 (no exact field) still
// means "unset" and is defaulted, so existing callers are unaffected.
func TestNewLimiter_PlainZeroRateStillDefaults(t *testing.T) {
	cfg := testConfig()
	cfg.IPRate = 0
	cfg.ASNRate = 0
	l := NewLimiter(cfg)

	if l.ipRate != DefaultConfig().IPRate {
		t.Fatalf("ipRate = %v, want default %v", l.ipRate, DefaultConfig().IPRate)
	}
	if l.asnRate != DefaultConfig().ASNRate {
		t.Fatalf("asnRate = %v, want default %v", l.asnRate, DefaultConfig().ASNRate)
	}
}

// A zero exact rate yields a bucket that allows only its initial burst and then
// denies (no sustained refill), which is the point of configuring rate 0.
func TestAllowIP_ExplicitZeroRateDeniesAfterBurst(t *testing.T) {
	cfg := testConfig()
	cfg.IPRateExact = ptrFloat(0)
	cfg.IPBurst = 3
	l := NewLimiter(cfg)

	ip := net.ParseIP("10.9.9.9")
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.AllowIP(ip) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed %d requests, want exactly 3 (burst) with zero sustained rate", allowed)
	}
}
