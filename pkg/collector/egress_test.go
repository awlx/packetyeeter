package collector

import (
	"net"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
)

// The kernel egress counters are cumulative and monotonic, so everything the
// analyzer sees depends on this diff being right. The cases that matter are the
// ones that are not a plain subtraction: a client seen for the first time, and
// a counter that appears to move backwards.
func TestDeltaEgressFirstObservationIsNotCredited(t *testing.T) {
	m := map[uint32]prevEgress{}
	now := time.Now()

	// A counter can have been accumulating long before the collector started
	// watching it. Reporting 5 GiB as a single poll interval's worth of traffic
	// would claim a transfer rate that never happened.
	if delta, ok := deltaEgress(m, 1, 5<<30, now); ok {
		t.Fatalf("first observation should not be credited, got delta=%d", delta)
	}

	if got := m[1].bytes; got != 5<<30 {
		t.Fatalf("first observation should still be recorded, got %d", got)
	}

	delta, ok := deltaEgress(m, 1, (5<<30)+1000, now.Add(time.Second))
	if !ok || delta != 1000 {
		t.Fatalf("want delta 1000 on second observation, got %d (ok=%v)", delta, ok)
	}
}

func TestDeltaEgressTreatsBackwardsCounterAsReset(t *testing.T) {
	m := map[uint32]prevEgress{}
	now := time.Now()

	deltaEgress(m, 1, 10_000, now)
	if delta, ok := deltaEgress(m, 1, 12_000, now.Add(time.Second)); !ok || delta != 2_000 {
		t.Fatalf("want delta 2000, got %d (ok=%v)", delta, ok)
	}

	// LRU eviction and reinsertion, or a collector restart, makes the counter
	// restart from a low value. Subtracting would underflow uint64 into an
	// astronomically large delta and instantly trip any byte threshold.
	delta, ok := deltaEgress(m, 1, 500, now.Add(2*time.Second))
	if !ok {
		t.Fatal("a reset counter with traffic on it should still be credited")
	}
	if delta != 500 {
		t.Fatalf("want the post-reset value 500 as the delta, got %d", delta)
	}
}

func TestDeltaEgressIgnoresIdleClients(t *testing.T) {
	m := map[uint32]prevEgress{}
	now := time.Now()

	deltaEgress(m, 1, 10_000, now)
	if _, ok := deltaEgress(m, 1, 10_000, now.Add(time.Second)); ok {
		t.Fatal("an unchanged counter should not produce a signal")
	}
}

func TestDeltaEgressResetToZeroProducesNothing(t *testing.T) {
	m := map[uint32]prevEgress{}
	now := time.Now()

	deltaEgress(m, 1, 10_000, now)
	// A freshly reinserted entry that has not been transmitted to yet carries
	// no evidence of anything, so it must not be reported.
	if _, ok := deltaEgress(m, 1, 0, now.Add(time.Second)); ok {
		t.Fatal("a reset counter with no traffic should not produce a signal")
	}
}

func TestDeltaEgressTracksClientsIndependently(t *testing.T) {
	m := map[uint32]prevEgress{}
	now := time.Now()

	deltaEgress(m, 1, 1_000, now)
	deltaEgress(m, 2, 50_000, now)

	if delta, ok := deltaEgress(m, 1, 3_000, now.Add(time.Second)); !ok || delta != 2_000 {
		t.Fatalf("client 1: want 2000, got %d (ok=%v)", delta, ok)
	}
	if delta, ok := deltaEgress(m, 2, 51_000, now.Add(time.Second)); !ok || delta != 1_000 {
		t.Fatalf("client 2: want 1000, got %d (ok=%v)", delta, ok)
	}
}

func TestPruneEgressStateDropsIdleClientsOnly(t *testing.T) {
	m := map[uint32]prevEgress{}
	now := time.Now()

	m[1] = prevEgress{bytes: 100, lastSeen: now.Add(-egressPrevStateTTL - time.Minute)}
	m[2] = prevEgress{bytes: 200, lastSeen: now}

	prunePrevEgressMap(m, now)

	if _, ok := m[1]; ok {
		t.Fatal("client idle beyond the TTL should have been pruned")
	}
	if _, ok := m[2]; !ok {
		t.Fatal("recently active client should have been kept")
	}
}

// A pruned client is indistinguishable from a new one, so it is not credited
// with its cumulative counter on the next poll. This is the whole reason the
// TTL has to exceed the analyzer's detection window.
func TestPrunedClientIsTreatedAsNew(t *testing.T) {
	m := map[uint32]prevEgress{}
	now := time.Now()

	deltaEgress(m, 1, 1<<30, now.Add(-egressPrevStateTTL-time.Minute))
	prunePrevEgressMap(m, now)

	if delta, ok := deltaEgress(m, 1, 1<<30, now); ok {
		t.Fatalf("a pruned client must not be credited with its counter, got %d", delta)
	}
}

// Signals are marshaled asynchronously off signalQueue, long after the poll
// loop has moved on. The IPv6 map iterator reuses one key array per poll, so a
// signal that kept a slice of it would report whichever address was iterated
// last - attributing one client's bytes to another, and eventually blocking the
// wrong client once enforcement is on.
func TestEmitEgressSignalCopiesCallerAddress(t *testing.T) {
	c := &Collector{
		Config:      Config{EgressMinBytes: 1},
		signalQueue: make(chan *apiv1.Signal, 4),
	}

	var key [16]byte
	copy(key[:], net.ParseIP("2001:db8::1").To16())

	if !c.emitEgressSignal(net.IP(key[:]), 1<<20, 1<<20, 1) {
		t.Fatal("signal not emitted")
	}

	// Simulate the iterator overwriting its key for the next entry.
	copy(key[:], net.ParseIP("2001:db8::2").To16())

	signal := <-c.signalQueue
	if got := net.IP(signal.Ip).String(); got != "2001:db8::1" {
		t.Fatalf("queued signal reports %s; the address aliased the caller's buffer", got)
	}
}
