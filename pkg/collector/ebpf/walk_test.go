package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// fakeMap models a uint32->uint64 hash map. With batch=false every batch op
// fails like a pre-5.6 kernel.
type fakeMap struct {
	batch      bool
	entries    map[uint32]uint64
	order      []uint32
	cursors    map[*ebpf.MapBatchCursor]int
	enospcOnce bool // first lookup fails with ENOSPC, as for an oversized bucket
	iterErr    error
	batchCalls int
	deletes    int
}

func newFakeMap(batch bool, n int) *fakeMap {
	m := &fakeMap{batch: batch, entries: map[uint32]uint64{}, cursors: map[*ebpf.MapBatchCursor]int{}}
	for i := 0; i < n; i++ {
		k := uint32(i*7 + 1)
		m.entries[k] = uint64(k) * 10
		m.order = append(m.order, k)
	}
	return m
}

func (m *fakeMap) String() string { return "fake" }

func (m *fakeMap) BatchLookup(c *ebpf.MapBatchCursor, keysOut, valuesOut any, _ *ebpf.BatchOptions) (int, error) {
	m.batchCalls++
	if !m.batch {
		return 0, fmt.Errorf("map batch lookup: %w", ebpf.ErrNotSupported)
	}
	if m.enospcOnce {
		m.enospcOnce = false
		return 0, fmt.Errorf("map batch lookup: %w (batch size too small?)", unix.ENOSPC)
	}
	keys, vals := keysOut.([]uint32), valuesOut.([]uint64)
	pos := m.cursors[c]
	n := 0
	for pos < len(m.order) && n < len(keys) {
		k := m.order[pos]
		pos++
		v, ok := m.entries[k]
		if !ok {
			continue
		}
		keys[n], vals[n] = k, v
		n++
	}
	m.cursors[c] = pos
	if pos >= len(m.order) {
		return n, fmt.Errorf("map batch lookup: %w", ebpf.ErrKeyNotExist)
	}
	return n, nil
}

func (m *fakeMap) BatchDelete(keys any, _ *ebpf.BatchOptions) (int, error) {
	if !m.batch {
		return 0, ebpf.ErrNotSupported
	}
	for i, k := range keys.([]uint32) {
		if _, ok := m.entries[k]; !ok {
			return i, fmt.Errorf("batch delete: %w", ebpf.ErrKeyNotExist)
		}
		delete(m.entries, k)
	}
	return len(keys.([]uint32)), nil
}

func (m *fakeMap) Delete(key any) error {
	m.deletes++
	k := *key.(*uint32)
	if _, ok := m.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, k)
	return nil
}

type fakeIter struct {
	m   *fakeMap
	pos int
}

func (it *fakeIter) Next(k, v any) bool {
	for it.pos < len(it.m.order) {
		key := it.m.order[it.pos]
		it.pos++
		if val, ok := it.m.entries[key]; ok {
			*k.(*uint32), *v.(*uint64) = key, val
			return true
		}
	}
	return false
}

func (it *fakeIter) Err() error { return it.m.iterErr }

func (m *fakeMap) iterate() entryIterator { return &fakeIter{m: m} }

func collect(t *testing.T, w *MapWalker, m *fakeMap) map[uint32]uint64 {
	t.Helper()
	got := map[uint32]uint64{}
	err := walk(w, m, func(k uint32, v uint64) bool {
		if _, dup := got[k]; dup {
			t.Fatalf("key %d visited twice", k)
		}
		got[k] = v
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func checkSame(t *testing.T, got map[uint32]uint64, m *fakeMap) {
	t.Helper()
	if len(got) != len(m.entries) {
		t.Fatalf("visited %d entries, map has %d", len(got), len(m.entries))
	}
	for k, v := range m.entries {
		if got[k] != v {
			t.Fatalf("key %d: got %d want %d", k, got[k], v)
		}
	}
}

func TestWalkBatchChunks(t *testing.T) {
	for _, n := range []int{0, 1, 3, 4, 5, 17} {
		m := newFakeMap(true, n)
		w := &MapWalker{Chunk: 4}
		checkSame(t, collect(t, w, m), m)
		if w.noBatch.Load() {
			t.Fatal("fell back on a batch-capable map")
		}
	}
}

func TestWalkBatchGrowsOnENOSPC(t *testing.T) {
	m := newFakeMap(true, 10)
	m.enospcOnce = true
	checkSame(t, collect(t, &MapWalker{Chunk: 2}, m), m)
}

func TestWalkStopsEarly(t *testing.T) {
	m := newFakeMap(true, 20)
	seen := 0
	err := walk(&MapWalker{Chunk: 4}, m, func(uint32, uint64) bool {
		seen++
		return seen < 6
	})
	if err != nil || seen != 6 {
		t.Fatalf("seen=%d err=%v", seen, err)
	}
}

func TestWalkFallsBackOnceWithoutBatchOps(t *testing.T) {
	var logs bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logs)
	w := &MapWalker{Chunk: 4, Logger: l}

	m := newFakeMap(false, 9)
	checkSame(t, collect(t, w, m), m)
	if !w.noBatch.Load() {
		t.Fatal("walker did not remember missing batch support")
	}
	calls := m.batchCalls
	checkSame(t, collect(t, w, m), m)
	if m.batchCalls != calls {
		t.Fatal("walker retried batch lookup after falling back")
	}
	if n := strings.Count(logs.String(), "per-key iteration"); n != 1 {
		t.Fatalf("fallback logged %d times, want 1:\n%s", n, logs.String())
	}
}

func TestWalkIterErrorSurfaces(t *testing.T) {
	m := newFakeMap(false, 3)
	m.iterErr = ebpf.ErrIterationAborted
	err := walk(&MapWalker{Logger: logrus.New()}, m, func(uint32, uint64) bool { return true })
	if !errors.Is(err, ebpf.ErrIterationAborted) {
		t.Fatalf("err = %v, want ErrIterationAborted", err)
	}
}

func TestWalkBatchErrorSurfaces(t *testing.T) {
	m := &errMap{fakeMap: newFakeMap(true, 3)}
	err := walk(&MapWalker{}, m, func(uint32, uint64) bool { return true })
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("err = %v, want EINVAL", err)
	}
}

type errMap struct{ *fakeMap }

func (m *errMap) BatchLookup(*ebpf.MapBatchCursor, any, any, *ebpf.BatchOptions) (int, error) {
	return 0, unix.EINVAL
}

func TestDeleteKeys(t *testing.T) {
	for _, batch := range []bool{true, false} {
		t.Run(fmt.Sprintf("batch=%v", batch), func(t *testing.T) {
			m := newFakeMap(batch, 20)
			keys := slices.Clone(m.order[:12])
			// Two keys vanish before the delete, as when the kernel completes
			// the handshake concurrently.
			delete(m.entries, keys[3])
			delete(m.entries, keys[9])

			var deleted []int
			w := &MapWalker{Chunk: 4, Logger: logrus.New()}
			missing, err := deleteKeys(w, m, keys, func(i int) { deleted = append(deleted, i) })
			if err != nil {
				t.Fatal(err)
			}
			if missing != 2 {
				t.Fatalf("missing = %d, want 2", missing)
			}
			want := []int{0, 1, 2, 4, 5, 6, 7, 8, 10, 11}
			if !slices.Equal(deleted, want) {
				t.Fatalf("deleted %v, want %v", deleted, want)
			}
			if len(m.entries) != 8 {
				t.Fatalf("%d entries left, want 8", len(m.entries))
			}
			for _, k := range m.order[12:] {
				if _, ok := m.entries[k]; !ok {
					t.Fatalf("untouched key %d deleted", k)
				}
			}
			if batch && m.deletes != 0 {
				t.Fatalf("batch-capable map used %d single deletes", m.deletes)
			}
		})
	}
}

func TestWalkReusesChunkBuffers(t *testing.T) {
	m := newFakeMap(true, 3)
	w := &MapWalker{}
	walk(w, m, func(uint32, uint64) bool { return true })
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 100; i++ {
		m.cursors = map[*ebpf.MapBatchCursor]int{}
		walk(w, m, func(uint32, uint64) bool { return true })
	}
	runtime.ReadMemStats(&after)
	// Fresh buffers would be 100 x 4096 x 12 bytes, about 4.7 MiB. The bound
	// leaves room for -race, where sync.Pool drops a quarter of its Puts.
	if d := after.TotalAlloc - before.TotalAlloc; d > 3<<20 {
		t.Fatalf("100 walks allocated %d bytes; chunk buffers not reused", d)
	}
}
