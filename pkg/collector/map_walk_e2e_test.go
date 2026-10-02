//go:build linux && e2e_ebpf

// Checks the batch map walker against MapIterator on real kernel maps shaped
// like the collector's (LRU hash, production max_entries), and that pending
// handshake consumption deletes exactly what it reports. Needs root; does not
// need the compiled eBPF object.
//
//	sudo -E go test -tags e2e_ebpf -run 'TestMapWalk|TestPendingHandshakeConsume' -v ./pkg/collector/
//
// Poll timing at full map size (prints ms per poll):
//
//	sudo -E PERF_N=3000000 go test -tags e2e_ebpf -run '^$' -bench BenchmarkPollICMPRatesSpoofed -benchtime 3x ./pkg/collector/
package collector

import (
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"
)

const (
	e2eRateMapSize      = 3_000_000 // BLOCK_MAP_SIZE
	e2eHandshakeMapSize = 500_000   // HANDSHAKES_MAP_SIZE
)

func newLRUMap(tb testing.TB, name string, keySize, valueSize, maxEntries uint32) *cebpf.Map {
	tb.Helper()
	m, err := cebpf.NewMap(&cebpf.MapSpec{
		Name: name, Type: cebpf.LRUHash, KeySize: keySize, ValueSize: valueSize, MaxEntries: maxEntries,
	})
	if err != nil {
		tb.Fatalf("create %s: %v", name, err)
	}
	tb.Cleanup(func() { m.Close() })
	return m
}

func batchFill[K, V any](tb testing.TB, m *cebpf.Map, n int, gen func(i int) (K, V)) {
	tb.Helper()
	const chunk = 100_000
	keys := make([]K, 0, chunk)
	vals := make([]V, 0, chunk)
	for i := 0; i < n; i++ {
		k, v := gen(i)
		keys = append(keys, k)
		vals = append(vals, v)
		if len(keys) == chunk || i == n-1 {
			if _, err := m.BatchUpdate(keys, vals, nil); err != nil {
				tb.Fatalf("fill: %v", err)
			}
			keys, vals = keys[:0], vals[:0]
		}
	}
}

// walkMatchesIterate compares the batch walk with MapIterator on an unchanging
// map: same key set, same values, no key twice.
func walkMatchesIterate[K comparable, V comparable](t *testing.T, m *cebpf.Map, chunk int) int {
	t.Helper()
	want := map[K]V{}
	var k K
	var v V
	it := m.Iterate()
	for it.Next(&k, &v) {
		want[k] = v
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	got := make(map[K]V, len(want))
	err := ebpf.Walk(&ebpf.MapWalker{Chunk: chunk}, m, func(k K, v V) bool {
		if _, dup := got[k]; dup {
			t.Fatalf("key %v visited twice", k)
		}
		got[k] = v
		return true
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("walk visited %d keys, iterate %d", len(got), len(want))
	}
	for k, wv := range want {
		gv, ok := got[k]
		if !ok {
			t.Fatalf("walk missed key %v", k)
		}
		if gv != wv {
			t.Fatalf("key %v: walk value %v, iterate %v", k, gv, wv)
		}
	}
	return len(want)
}

func TestMapWalkMatchesIterate(t *testing.T) {
	requireRoot(t)
	defer runtime.GC()

	t.Run("icmp_rates", func(t *testing.T) {
		m := newLRUMap(t, "icmp_rates", 4, 24, e2eRateMapSize)
		batchFill(t, m, 1_000_000, func(i int) (uint32, ebpf.ICMPRate) {
			return uint32(0x0a000000 + i), ebpf.ICMPRate{LastTime: uint64(i), Count: uint64(i % 5000)}
		})
		for _, chunk := range []int{1, 4096} {
			if chunk == 1 {
				// A one-entry buffer exercises the ENOSPC regrow on multi-entry
				// buckets; a smaller map keeps it quick.
				small := newLRUMap(t, "icmp_small", 4, 24, 20_000)
				batchFill(t, small, 20_000, func(i int) (uint32, ebpf.ICMPRate) {
					return uint32(i), ebpf.ICMPRate{Count: uint64(i)}
				})
				n := walkMatchesIterate[uint32, ebpf.ICMPRate](t, small, chunk)
				t.Logf("chunk=1: %d entries", n)
				continue
			}
			n := walkMatchesIterate[uint32, ebpf.ICMPRate](t, m, chunk)
			t.Logf("chunk=%d: %d entries", chunk, n)
		}
	})

	t.Run("icmp_rates_v6", func(t *testing.T) {
		m := newLRUMap(t, "icmp_rates_v6", 16, 24, e2eRateMapSize)
		batchFill(t, m, 500_000, func(i int) ([16]byte, ebpf.ICMPRate) {
			var k [16]byte
			k[0], k[1] = 0x20, 0x01
			binary.BigEndian.PutUint32(k[12:], uint32(i))
			return k, ebpf.ICMPRate{LastTime: uint64(i), Count: 3}
		})
		t.Logf("%d entries", walkMatchesIterate[[16]byte, ebpf.ICMPRate](t, m, ebpf.DefaultWalkChunk))
	})

	t.Run("pending_handshakes", func(t *testing.T) {
		m := newLRUMap(t, "pending_hs", 12, 24, e2eHandshakeMapSize)
		batchFill(t, m, 400_000, func(i int) (ebpf.TcpSessionKey, ebpf.HandshakeStatusGeneric) {
			return ebpf.TcpSessionKey{Saddr: uint32(0x0a000000 + i%5000), Daddr: 1, Sport: uint16(i / 5000), Dport: 443},
				ebpf.HandshakeStatusGeneric{BeginTime: uint64(i + 1), SynAckTime: uint64(i + 2), SynAckSent: 1}
		})
		t.Logf("%d entries", walkMatchesIterate[ebpf.TcpSessionKey, ebpf.HandshakeStatusGeneric](t, m, ebpf.DefaultWalkChunk))
	})
}

func TestDeleteKeysOnKernelMap(t *testing.T) {
	requireRoot(t)
	m := newLRUMap(t, "pending_hs", 12, 24, 100_000)
	const n = 10_000
	batchFill(t, m, n, func(i int) (ebpf.TcpSessionKey, ebpf.HandshakeStatusGeneric) {
		return ebpf.TcpSessionKey{Saddr: uint32(i), Dport: 80}, ebpf.HandshakeStatusGeneric{BeginTime: 1}
	})
	var keys []ebpf.TcpSessionKey
	for i := 0; i < n; i += 2 {
		keys = append(keys, ebpf.TcpSessionKey{Saddr: uint32(i), Dport: 80})
	}
	// Vanish a few in the middle of different chunks, as a completing
	// handshake would between walk and delete.
	gone := map[int]bool{5: true, 100: true, 4096: true, 4097: true, len(keys) - 1: true}
	for i := range gone {
		if err := m.Delete(&keys[i]); err != nil {
			t.Fatal(err)
		}
	}
	deleted := map[int]bool{}
	missing, err := ebpf.DeleteKeys(&ebpf.MapWalker{}, m, keys, func(i int) { deleted[i] = true })
	if err != nil {
		t.Fatal(err)
	}
	if missing != len(gone) {
		t.Fatalf("missing = %d, want %d", missing, len(gone))
	}
	for i := range keys {
		if deleted[i] == gone[i] {
			t.Fatalf("key %d: deleted=%v, vanished beforehand=%v", i, deleted[i], gone[i])
		}
	}
	var k ebpf.TcpSessionKey
	var v ebpf.HandshakeStatusGeneric
	left := 0
	it := m.Iterate()
	for it.Next(&k, &v) {
		if k.Saddr%2 == 0 {
			t.Fatalf("consumed key %+v still present", k)
		}
		left++
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	if left != n/2 {
		t.Fatalf("%d keys left, want %d", left, n/2)
	}
}

func quietCollector(maps *ebpf.Maps) *Collector {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return &Collector{
		Config:             Config{PollInterval: time.Second, HandshakeTimeout: time.Second},
		Logger:             l,
		signalQueue:        make(chan *apiv1.Signal, 100_000),
		prevICMPRates:      map[uint32]prevRate{},
		prevUDPRates:       map[uint32]prevRate{},
		prevICMPRatesV6:    map[[16]byte]prevRate{},
		prevUDPRatesV6:     map[[16]byte]prevRate{},
		prevBadFlagsSeen:   map[uint32]uint64{},
		prevBadFlagsSeenV6: map[[16]byte]uint64{},
		Maps:               maps,
	}
}

func TestPendingHandshakeConsumeOnKernelMap(t *testing.T) {
	requireRoot(t)
	now, err := monotonicNowNS()
	if err != nil {
		t.Fatal(err)
	}
	expired := now - uint64(10*time.Second)
	fresh := now

	m4 := newLRUMap(t, "pending_hs", 12, 24, e2eHandshakeMapSize)
	m6 := newLRUMap(t, "pending_hs6", 36, 24, e2eHandshakeMapSize)
	// 3 sources x 3000 expired + 2000 fresh each; v6 mirrors it.
	batchFill(t, m4, 15_000, func(i int) (ebpf.TcpSessionKey, ebpf.HandshakeStatusGeneric) {
		begin := expired
		if i%5 >= 3 {
			begin = fresh
		}
		return ebpf.TcpSessionKey{Saddr: uint32(0x0a000001 + i%3), Daddr: 2, Sport: uint16(i), Dport: uint16(i % 7)},
			ebpf.HandshakeStatusGeneric{BeginTime: begin}
	})
	batchFill(t, m6, 15_000, func(i int) (ebpf.TcpSessionKeyV6, ebpf.HandshakeStatusGeneric) {
		begin := expired
		if i%5 >= 3 {
			begin = fresh
		}
		var s [16]byte
		s[0], s[1], s[15] = 0x20, 0x01, byte(1+i%3)
		return ebpf.TcpSessionKeyV6{Saddr: s, Sport: uint16(i), Dport: uint16(i % 7)}, ebpf.HandshakeStatusGeneric{BeginTime: begin}
	})

	c := quietCollector(&ebpf.Maps{PendingHandshakes: m4, PendingHandshakesV6: m6})
	c.sendPendingHandshakes()

	counts := map[string]uint32{}
	for len(c.signalQueue) > 0 {
		s := <-c.signalQueue
		counts[s.Id] = s.TcpContext.SynCount
	}
	if len(counts) != 6 {
		t.Fatalf("got %d signals, want 6: %v", len(counts), counts)
	}
	for id, n := range counts {
		if n != 3000 {
			t.Fatalf("%s SynCount = %d, want 3000", id, n)
		}
	}
	checkFresh := func(name string, v ebpf.HandshakeStatusGeneric, left *int) bool {
		if v.BeginTime != fresh {
			t.Fatalf("%s: expired entry survived consume", name)
		}
		*left++
		return true
	}
	left4, left6 := 0, 0
	if err := ebpf.Walk(&ebpf.MapWalker{}, m4, func(_ ebpf.TcpSessionKey, v ebpf.HandshakeStatusGeneric) bool {
		return checkFresh("v4", v, &left4)
	}); err != nil {
		t.Fatal(err)
	}
	if err := ebpf.Walk(&ebpf.MapWalker{}, m6, func(_ ebpf.TcpSessionKeyV6, v ebpf.HandshakeStatusGeneric) bool {
		return checkFresh("v6", v, &left6)
	}); err != nil {
		t.Fatal(err)
	}
	if left4 != 6000 || left6 != 6000 {
		t.Fatalf("entries left v4=%d v6=%d, want 6000 fresh each", left4, left6)
	}

	// A second poll must not re-report consumed handshakes.
	c.sendPendingHandshakes()
	if len(c.signalQueue) != 0 {
		t.Fatalf("second poll emitted %d signals", len(c.signalQueue))
	}
}

func envIntDefault(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

// BenchmarkPollICMPRatesSpoofed times one sendICMPRates poll over an
// icmp_rates map full of sub-threshold sources, the spoofed-flood case.
func BenchmarkPollICMPRatesSpoofed(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires root")
	}
	n := envIntDefault("PERF_N", 1_000_000)
	m, err := cebpf.NewMap(&cebpf.MapSpec{Name: "icmp_rates", Type: cebpf.LRUHash, KeySize: 4, ValueSize: 24, MaxEntries: e2eRateMapSize})
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()
	now, _ := monotonicNowNS()
	batchFill(b, m, n, func(i int) (uint32, ebpf.ICMPRate) {
		return uint32(0x0a000000 + i), ebpf.ICMPRate{LastTime: now, Count: 3}
	})
	c := quietCollector(&ebpf.Maps{ICMPRates: m})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.sendICMPRates()
	}
	b.StopTimer()
	b.ReportMetric(float64(len(c.prevICMPRates)), "prev-entries")
	if len(c.signalQueue) != 0 {
		b.Fatalf("sub-threshold sources emitted %d signals", len(c.signalQueue))
	}
}
