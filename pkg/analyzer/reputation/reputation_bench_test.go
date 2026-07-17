package reputation

import (
	"strconv"
	"testing"
	"time"
)

// Once a shard is at its per-shard budget, every Penalize for a new key
// triggers a prune. Under a distinct-IP flood essentially every signal
// creates a new key, so prune cost is paid per signal under the shard's
// write lock — this measures that worst case.
func BenchmarkPenalizeDistinctKeysAtCap(b *testing.B) {
	e := New(time.Minute, 0.5, 100)
	fill := int(e.maxEntries.Load())
	for i := 0; i < fill; i++ {
		e.Penalize("192.0.2."+strconv.Itoa(i), TypeIP, 1.0, "bench-fill")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Penalize("198.51.100."+strconv.Itoa(fill+i), TypeIP, 1.0, "bench")
	}
}
