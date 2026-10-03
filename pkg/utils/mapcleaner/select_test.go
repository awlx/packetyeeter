package mapcleaner

import (
	"math/rand"
	"slices"
	"testing"
	"time"
)

// removeOldestNSort is the sort-based implementation RemoveOldestN replaced,
// kept as the reference the selection must agree with.
func removeOldestNSort[K comparable, V any](m map[K]V, n int, getTimestamp func(K, V) time.Time) {
	if n <= 0 || len(m) == 0 {
		return
	}
	if n >= len(m) {
		clear(m)
		return
	}
	type entry struct {
		key K
		ts  time.Time
	}
	entries := make([]entry, 0, len(m))
	for key, value := range m {
		entries = append(entries, entry{key: key, ts: getTimestamp(key, value)})
	}
	slices.SortFunc(entries, func(a, b entry) int { return a.ts.Compare(b.ts) })
	for i := range n {
		delete(m, entries[i].key)
	}
}

func evictedTimes(before, after map[int]stamped) []time.Time {
	var out []time.Time
	for k, v := range before {
		if _, ok := after[k]; !ok {
			out = append(out, v.ts)
		}
	}
	slices.SortFunc(out, time.Time.Compare)
	return out
}

func TestSelectMatchesSort(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	base := time.Now()
	ts := func(_ int, v stamped) time.Time { return v.ts }
	for iter := 0; iter < 300; iter++ {
		size := 1 + r.Intn(3000)
		// Small spreads force many ties, including at the eviction boundary.
		spread := []int64{1, 3, 50, int64(time.Hour)}[r.Intn(4)]
		unique := r.Intn(2) == 0
		src := make(map[int]stamped, size)
		for i := range size {
			off := r.Int63n(spread)
			if unique {
				off = int64(i)*int64(time.Millisecond) + r.Int63n(int64(time.Millisecond))
			}
			src[i] = stamped{ts: base.Add(time.Duration(off))}
		}
		if unique {
			// Shuffle so insertion order does not follow timestamp order.
			keys := r.Perm(size)
			shuffled := make(map[int]stamped, size)
			for i, k := range keys {
				shuffled[k] = src[i]
			}
			src = shuffled
		}
		n := r.Intn(size + 2)

		got, want := cloneStamped(src), cloneStamped(src)
		RemoveOldestN(got, n, ts)
		removeOldestNSort(want, n, ts)

		if len(got) != len(want) {
			t.Fatalf("iter %d: len got %d want %d", iter, len(got), len(want))
		}
		gotEv, wantEv := evictedTimes(src, got), evictedTimes(src, want)
		if !slices.EqualFunc(gotEv, wantEv, time.Time.Equal) {
			t.Fatalf("iter %d: evicted timestamps differ from sort reference", iter)
		}
		if unique {
			for k := range want {
				if _, ok := got[k]; !ok {
					t.Fatalf("iter %d: key %d kept by sort but evicted by select", iter, k)
				}
			}
		}
		// Every evicted entry is at least as old as every survivor.
		if len(gotEv) > 0 {
			newestEvicted := gotEv[len(gotEv)-1]
			for _, v := range got {
				if v.ts.Before(newestEvicted) {
					t.Fatalf("iter %d: survivor older than an evicted entry", iter)
				}
			}
		}
	}
}

func cloneStamped(m map[int]stamped) map[int]stamped {
	c := make(map[int]stamped, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// Adversarial inputs for pivot choice must still select correctly.
func TestSelectOldestSortedAndConstantInputs(t *testing.T) {
	for _, name := range []string{"ascending", "descending", "constant", "organ"} {
		const size = 5000
		e := make([]oldestEntry[int], size)
		for i := range e {
			var age int64
			switch name {
			case "ascending":
				age = int64(i)
			case "descending":
				age = int64(size - i)
			case "constant":
				age = 7
			case "organ":
				age = int64(min(i, size-i))
			}
			e[i] = oldestEntry[int]{key: i, age: age}
		}
		ref := slices.Clone(e)
		slices.SortFunc(ref, func(a, b oldestEntry[int]) int { return int(a.age - b.age) })
		for _, n := range []int{1, 17, size / 2, size - 1} {
			c := slices.Clone(e)
			selectOldest(c, n)
			var maxSel int64 = -1 << 63
			for _, x := range c[:n] {
				maxSel = max(maxSel, x.age)
			}
			if maxSel != ref[n-1].age {
				t.Fatalf("%s n=%d: n-th oldest %d, want %d", name, n, maxSel, ref[n-1].age)
			}
			for _, x := range c[n:] {
				if x.age < maxSel {
					t.Fatalf("%s n=%d: kept age %d below selected max %d", name, n, x.age, maxSel)
				}
			}
		}
	}
}
