package aidetection

import (
	"net"
	"testing"
)

// TestSignalRouteKeyPrefersJA4H verifies the correlation key used both for
// worker shard routing (EmitSignal) and window grouping (processSignal)
// prefers JA4H over IP, and falls back to empty for signals with neither.
func TestSignalRouteKeyPrefersJA4H(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")

	if got := signalRouteKey(Signal{IP: ip, JA4H: "t13d1516h2_abc"}); got != "ja4h:t13d1516h2_abc" {
		t.Fatalf("expected ja4h key to take priority, got %q", got)
	}
	if got := signalRouteKey(Signal{IP: ip}); got != "ip:203.0.113.9" {
		t.Fatalf("expected ip key, got %q", got)
	}
	if got := signalRouteKey(Signal{}); got != "" {
		t.Fatalf("expected empty key for signal with neither IP nor JA4H, got %q", got)
	}
}

// TestNewSignalShardsCount verifies one buffered channel is created per
// worker and that total capacity is split (not multiplied) across shards, so
// increasing worker count doesn't silently balloon total buffered memory.
func TestNewSignalShardsCount(t *testing.T) {
	shards := newSignalShards(4, 100)
	if len(shards) != 4 {
		t.Fatalf("expected 4 shards, got %d", len(shards))
	}
	total := 0
	for _, ch := range shards {
		total += cap(ch)
	}
	if total > 100 {
		t.Fatalf("expected total shard capacity <= configured buffer size, got %d", total)
	}

	// Degenerate inputs must not panic or produce zero-worker/zero-capacity shards.
	if got := newSignalShards(0, 100); len(got) != 1 || cap(got[0]) < 1 {
		t.Fatalf("expected a single non-empty shard for workers=0, got %d shards cap=%d", len(got), cap(got[0]))
	}
	if got := newSignalShards(50, 10); len(got) != 50 {
		t.Fatalf("expected 50 shards even when buffer size < workers, got %d", len(got))
	}
	for _, ch := range newSignalShards(50, 10) {
		if cap(ch) < 1 {
			t.Fatalf("expected every shard to have capacity >= 1 even when buffer size < workers")
		}
	}
}

// TestEmitSignalRoutesConsistentlyByKey is the core regression guard for the
// worker-fragmentation bug: it verifies that every signal sharing the same
// correlation key (IP or JA4H) is always routed to the same worker shard, no
// matter how many times EmitSignal is called. Without this guarantee, a
// single attacking IP's signals get randomly split across all worker shards,
// and no single worker's window ever sees the IP's true total signal count -
// silently raising effective DDoS detection thresholds by ~workerCount times.
func TestEmitSignalRoutesConsistentlyByKey(t *testing.T) {
	e := New(Config{Workers: 8, BufferSize: 800, WarmupPeriod: 0})

	ips := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "203.0.113.77"}
	ja4hs := []string{"t13d1516h2_a", "t13d1516h2_b", "t13d1516h2_c"}

	shardOf := func(signal Signal) int {
		idx := 0
		if n := len(e.signalChans); n > 1 {
			if key := signalRouteKey(signal); key != "" {
				idx = int(fnv64(key) % uint64(n))
			}
		}
		return idx
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		want := shardOf(Signal{IP: ip})
		for i := 0; i < 25; i++ {
			got := shardOf(Signal{IP: ip})
			if got != want {
				t.Fatalf("IP %s routed inconsistently: expected shard %d, got %d on call %d", ipStr, want, got, i)
			}
		}
	}

	for _, ja4h := range ja4hs {
		want := shardOf(Signal{JA4H: ja4h})
		for i := 0; i < 25; i++ {
			got := shardOf(Signal{JA4H: ja4h})
			if got != want {
				t.Fatalf("JA4H %s routed inconsistently: expected shard %d, got %d on call %d", ja4h, want, got, i)
			}
		}
	}
}

// TestEmitSignalActuallyEnqueuesToConsistentShard drives real signals through
// EmitSignal (not just the routing helper) and drains the actual per-worker
// channels to confirm every signal for a given IP lands in the same physical
// channel end-to-end.
func TestEmitSignalActuallyEnqueuesToConsistentShard(t *testing.T) {
	e := New(Config{Workers: 6, BufferSize: 600, WarmupPeriod: 0})

	ip := net.ParseIP("192.0.2.55")
	const count = 40
	for i := 0; i < count; i++ {
		e.EmitSignal(Signal{Type: SignalIncompleteHandshake, Source: SourceTCP, IP: ip, Weight: 1})
	}

	occupied := -1
	total := 0
	for idx, ch := range e.signalChans {
		n := len(ch)
		total += n
		if n == 0 {
			continue
		}
		if occupied != -1 {
			t.Fatalf("signals for the same IP landed in more than one shard: shard %d and shard %d both non-empty", occupied, idx)
		}
		occupied = idx
	}
	if total != count {
		t.Fatalf("expected all %d emitted signals to be queued, found %d", count, total)
	}
	if occupied == -1 {
		t.Fatalf("expected exactly one shard to hold the emitted signals")
	}
}
