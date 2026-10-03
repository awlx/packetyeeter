package mapcleaner

import (
	"math/rand"
	"testing"
	"time"
)

func benchMap(n int) map[int]stamped {
	r := rand.New(rand.NewSource(1))
	base := time.Now()
	m := make(map[int]stamped, n)
	for i := range n {
		m[i] = stamped{ts: base.Add(time.Duration(r.Int63n(int64(time.Hour))))}
	}
	return m
}

// One over-cap eviction at a 100k cap, as a unique-IP flood triggers it.
func BenchmarkEnforceMaxSizeBatch100k(b *testing.B) {
	const maxSize = 100000
	src := benchMap(maxSize + 1)
	ts := func(_ int, v stamped) time.Time { return v.ts }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := make(map[int]stamped, len(src))
		for k, v := range src {
			m[k] = v
		}
		b.StartTimer()
		EnforceMaxSizeBatch(m, maxSize, ts)
	}
}
