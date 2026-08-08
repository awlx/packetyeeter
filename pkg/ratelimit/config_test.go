package ratelimit

import (
	"testing"
	"time"
)

// A partial config used to bypass defaulting entirely (only IPRate==0
// triggered it), letting CleanupInterval==0 reach time.NewTicker(0), which
// panics on the cleanup goroutine.
func TestNewLimiterDefaultsPartialConfig(t *testing.T) {
	l := NewLimiter(Config{IPRate: 50})

	if l.cleanupInterval <= 0 || l.maxAge <= 0 {
		t.Fatalf("cleanup fields not defaulted: interval=%v maxAge=%v", l.cleanupInterval, l.maxAge)
	}
	if l.ipRate != 50 {
		t.Fatalf("explicit IPRate overridden: %v", l.ipRate)
	}
	if l.asnRate <= 0 || l.ipBurst <= 0 || l.asnBurst <= 0 {
		t.Fatalf("rate/burst fields not defaulted: asnRate=%v ipBurst=%v asnBurst=%v", l.asnRate, l.ipBurst, l.asnBurst)
	}
	// Give the cleanup goroutine a moment; with the old behavior it panics
	// the process via time.NewTicker(0).
	time.Sleep(10 * time.Millisecond)
}
