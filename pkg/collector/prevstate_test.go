package collector

import "testing"

// The userspace prev-state maps shadow LRU kernel maps and must not grow for the
// process lifetime. These tests lock in the timestamp-window and hard-cap
// bounding so a high-cardinality flood cannot leak memory.

func TestPrunePrevRateMapDropsStale(t *testing.T) {
	now := prevStateStaleWindowNs * 2
	m := map[uint32]prevRate{
		1: {lastTime: now, count: 5},                              // fresh
		2: {lastTime: now - prevStateStaleWindowNs/2, count: 3},   // within window
		3: {lastTime: now - prevStateStaleWindowNs - 1, count: 9}, // stale
		4: {lastTime: 1, count: 1},                                // ancient
	}
	prunePrevRateMap(m, now, nil)
	if _, ok := m[1]; !ok {
		t.Errorf("fresh entry 1 was pruned")
	}
	if _, ok := m[2]; !ok {
		t.Errorf("in-window entry 2 was pruned")
	}
	if _, ok := m[3]; ok {
		t.Errorf("stale entry 3 was not pruned")
	}
	if _, ok := m[4]; ok {
		t.Errorf("ancient entry 4 was not pruned")
	}
}

func TestPrunePrevRateMapHardCapReset(t *testing.T) {
	m := make(map[uint32]prevRate, prevStateHardCap+10)
	// All entries fresh (same clock) so the window prune keeps them; only the
	// hard cap can bound this adversarial burst.
	for i := 0; i < prevStateHardCap+5; i++ {
		m[uint32(i)] = prevRate{lastTime: prevStateStaleWindowNs * 2, count: 1}
	}
	prunePrevRateMap(m, prevStateStaleWindowNs*2, nil)
	if len(m) != 0 {
		t.Errorf("hard-cap reset expected empty map, got %d entries", len(m))
	}
}

func TestPrunePrevSeenMapDropsStale(t *testing.T) {
	now := prevStateStaleWindowNs * 2
	m := map[uint32]uint64{
		10: now,
		11: now - prevStateStaleWindowNs - 1,
		12: 1,
	}
	prunePrevSeenMap(m, now, nil)
	if _, ok := m[10]; !ok {
		t.Errorf("fresh seen entry 10 was pruned")
	}
	if _, ok := m[11]; ok {
		t.Errorf("stale seen entry 11 was not pruned")
	}
	if _, ok := m[12]; ok {
		t.Errorf("ancient seen entry 12 was not pruned")
	}
}

func TestPrunePrevRateMapV6DropsStale(t *testing.T) {
	now := prevStateStaleWindowNs * 2
	var fresh, stale [16]byte
	fresh[15] = 1
	stale[15] = 2
	m := map[[16]byte]prevRate{
		fresh: {lastTime: now, count: 5},
		stale: {lastTime: now - prevStateStaleWindowNs - 1, count: 3},
	}
	prunePrevRateMapV6(m, now, nil)
	if _, ok := m[fresh]; !ok {
		t.Errorf("fresh v6 rate entry was pruned")
	}
	if _, ok := m[stale]; ok {
		t.Errorf("stale v6 rate entry was not pruned")
	}
}

func TestPrunePrevSeenMapV6Key(t *testing.T) {
	now := prevStateStaleWindowNs * 2
	var fresh, stale [16]byte
	fresh[15] = 1
	stale[15] = 2
	m := map[[16]byte]uint64{
		fresh: now,
		stale: now - prevStateStaleWindowNs - 1,
	}
	prunePrevSeenMap(m, now, nil)
	if _, ok := m[fresh]; !ok {
		t.Errorf("fresh v6 seen entry was pruned")
	}
	if _, ok := m[stale]; ok {
		t.Errorf("stale v6 seen entry was not pruned")
	}
}

// When no source has been observed recently (maxClock below the window), nothing
// should be pruned: a quiet system must not thrash its own bookkeeping.
func TestPrunePrevRateMapNoClockKeepsAll(t *testing.T) {
	m := map[uint32]prevRate{1: {lastTime: 5, count: 1}, 2: {lastTime: 9, count: 1}}
	prunePrevRateMap(m, 10, nil)
	if len(m) != 2 {
		t.Errorf("expected all entries retained when clock below window, got %d", len(m))
	}
}
