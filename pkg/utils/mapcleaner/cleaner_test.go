package mapcleaner

import (
	"testing"
	"time"
)

type stamped struct{ ts time.Time }

func TestRemoveOldestNRemovesExactlyTheOldest(t *testing.T) {
	base := time.Now()
	m := map[int]stamped{}
	for i := range 10 {
		m[i] = stamped{ts: base.Add(time.Duration(i) * time.Second)}
	}

	RemoveOldestN(m, 3, func(_ int, v stamped) time.Time { return v.ts })

	if len(m) != 7 {
		t.Fatalf("len = %d, want 7", len(m))
	}
	for i := range 3 {
		if _, ok := m[i]; ok {
			t.Fatalf("oldest key %d survived eviction", i)
		}
	}
	for i := 3; i < 10; i++ {
		if _, ok := m[i]; !ok {
			t.Fatalf("newer key %d was evicted", i)
		}
	}
}

func TestEnforceMaxSizeBatchLeavesHeadroom(t *testing.T) {
	base := time.Now()
	m := map[int]stamped{}
	for i := range 105 {
		m[i] = stamped{ts: base.Add(time.Duration(i) * time.Second)}
	}

	EnforceMaxSizeBatch(m, 100, func(_ int, v stamped) time.Time { return v.ts })

	// Removes the overflow (5) plus a 100/batchEvictHeadroom margin, leaving
	// ~90% of the cap so the O(n) scan amortizes over subsequent inserts.
	if want := 100 - 100/batchEvictHeadroom; len(m) != want {
		t.Fatalf("len = %d, want %d", len(m), want)
	}
	for i := range 105 - len(m) { // the oldest keys are the evicted ones
		if _, ok := m[i]; ok {
			t.Fatalf("oldest key %d survived batch eviction", i)
		}
	}
}

func TestEnforceMaxSizeBatchNoopUnderCapOrNonPositive(t *testing.T) {
	m := map[int]stamped{1: {}, 2: {}, 3: {}}
	getTS := func(_ int, v stamped) time.Time { return v.ts }

	EnforceMaxSizeBatch(m, 10, getTS) // under cap
	if len(m) != 3 {
		t.Fatalf("under-cap map mutated: len = %d, want 3", len(m))
	}
	EnforceMaxSizeBatch(m, 0, getTS) // maxSize <= 0
	if len(m) != 3 {
		t.Fatalf("maxSize<=0 must be a no-op: len = %d, want 3", len(m))
	}
}

func TestRemoveOldestNBounds(t *testing.T) {
	m := map[int]stamped{1: {ts: time.Now()}}
	RemoveOldestN(m, 0, func(_ int, v stamped) time.Time { return v.ts })
	if len(m) != 1 {
		t.Fatal("n=0 must be a no-op")
	}
	RemoveOldestN(m, 5, func(_ int, v stamped) time.Time { return v.ts })
	if len(m) != 0 {
		t.Fatal("n >= len must clear the map")
	}
}
