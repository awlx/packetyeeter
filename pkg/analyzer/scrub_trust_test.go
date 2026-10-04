package analyzer

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestEvidenceSetTTLAndRefresh(t *testing.T) {
	e := newEvidenceSet(time.Minute, 10)
	ip := net.ParseIP("192.0.2.1")
	t0 := time.Now()

	e.addAt(ip, t0)
	if !e.hasAt(ip, t0.Add(59*time.Second)) {
		t.Fatal("entry within TTL not found")
	}
	if e.hasAt(ip, t0.Add(time.Minute)) {
		t.Fatal("entry at TTL still found")
	}

	// Within the refresh window the timestamp is not rewritten.
	e.addAt(ip, t0.Add(scrubEvidenceRefresh/2))
	if e.hasAt(ip, t0.Add(time.Minute)) {
		t.Fatal("re-add within the refresh window extended the entry")
	}
	e.addAt(ip, t0.Add(scrubEvidenceRefresh))
	if !e.hasAt(ip, t0.Add(time.Minute)) {
		t.Fatal("re-add after the refresh window did not extend the entry")
	}

	if n := e.purge(t0.Add(scrubEvidenceRefresh + time.Minute)); n != 0 {
		t.Fatalf("purge left %d entries, want 0", n)
	}
	var nilSet *evidenceSet
	nilSet.add(ip)
	if nilSet.has(ip) || nilSet.purge(t0) != 0 {
		t.Fatal("nil set not empty")
	}
}

func TestEvidenceSetEvictsAtCapacity(t *testing.T) {
	const capacity = 50
	e := newEvidenceSet(time.Hour, capacity)
	t0 := time.Now()
	for i := range capacity {
		e.addAt(benchIP(i), t0.Add(time.Duration(i)*time.Second))
	}
	for i := range 2 * capacity {
		ip := benchIP(capacity + i)
		e.addAt(ip, t0.Add(time.Hour/2))
		if n := e.len(); n != capacity {
			t.Fatalf("size = %d after insert at capacity, want %d", n, capacity)
		}
		if !e.hasAt(ip, t0.Add(time.Hour/2)) {
			t.Fatalf("new entry %v not stored", ip)
		}
	}
	// Refreshing an existing key at capacity evicts nothing.
	existing := benchIP(2*capacity + capacity - 1)
	e.addAt(existing, t0.Add(time.Hour/2+time.Minute))
	if n := e.len(); n != capacity {
		t.Fatalf("size = %d after refresh, want %d", n, capacity)
	}
}

// Inserts into a full set must cost the same at any capacity: ns/op at
// cap=200000 should match cap=1000, not grow with it.
func BenchmarkEvidenceSetAddAtCapacity(b *testing.B) {
	for _, capacity := range []int{1000, 200000} {
		b.Run(fmt.Sprintf("cap=%d", capacity), func(b *testing.B) {
			e := newEvidenceSet(time.Hour, capacity)
			now := time.Now()
			for i := range capacity {
				e.addAt(benchIP(i), now)
			}
			ips := make([]net.IP, 1<<16)
			for i := range ips {
				ips[i] = benchIP(capacity + i)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.addAt(ips[i&(len(ips)-1)], now)
			}
		})
	}
}
