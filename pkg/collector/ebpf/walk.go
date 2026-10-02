package ebpf

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	DefaultWalkChunk = 4096
	maxWalkChunk     = 1 << 20
)

// MapWalker reads and deletes hash map entries with batch syscalls. Batch
// map ops need Linux 5.6+, so on older kernels it falls back to per-key
// iteration for the rest of the process lifetime. The zero value is usable.
type MapWalker struct {
	Chunk  int
	Logger logrus.FieldLogger

	noBatch  atomic.Bool
	fallOnce sync.Once
}

type entryIterator interface {
	Next(keyOut, valueOut any) bool
	Err() error
}

type walkMap interface {
	BatchLookup(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error)
	BatchDelete(keys any, opts *ebpf.BatchOptions) (int, error)
	Delete(key any) error
	iterate() entryIterator
	String() string
}

type ciliumMap struct{ *ebpf.Map }

func (m ciliumMap) iterate() entryIterator { return m.Map.Iterate() }

func (w *MapWalker) chunk() int {
	if w.Chunk > 0 {
		return w.Chunk
	}
	return DefaultWalkChunk
}

func (w *MapWalker) fallBack(err error) {
	w.noBatch.Store(true)
	w.fallOnce.Do(func() {
		logger := w.Logger
		if logger == nil {
			logger = logrus.StandardLogger()
		}
		logger.WithError(err).Info("Kernel lacks batch map operations (Linux 5.6+); polling maps with per-key iteration")
	})
}

// Walk calls fn for every entry of m until fn returns false. The batch path
// does not abort under concurrent inserts the way MapIterator does on a
// churning LRU map. Each key is visited at most once; entries inserted
// during the walk may or may not be seen.
func Walk[K, V any](w *MapWalker, m *ebpf.Map, fn func(K, V) bool) error {
	return walk(w, ciliumMap{m}, fn)
}

func walk[K, V any](w *MapWalker, m walkMap, fn func(K, V) bool) error {
	if !w.noBatch.Load() {
		unsupported, err := walkBatch(w.chunk(), m, fn)
		if !unsupported {
			return err
		}
		w.fallBack(err)
	}
	return walkIter(m, fn)
}

// walkBatch reports unsupported only if the very first lookup failed for lack
// of kernel support, so nothing has been passed to fn yet.
func walkBatch[K, V any](chunk int, m walkMap, fn func(K, V) bool) (unsupported bool, err error) {
	buf := getWalkBuf[K, V](chunk)
	defer walkBufPool[K, V]().Put(buf)
	keys, vals := buf.keys[:chunk], buf.vals[:chunk]
	var cursor ebpf.MapBatchCursor
	first := true
	for {
		n, err := m.BatchLookup(&cursor, keys, vals, nil)
		if n == 0 && errors.Is(err, unix.ENOSPC) && len(keys) < maxWalkChunk {
			// One hash bucket holds more entries than the buffer; the kernel
			// leaves the cursor on that bucket, so retry it with more room.
			keys = make([]K, 2*len(keys))
			vals = make([]V, 2*len(vals))
			buf.keys, buf.vals = keys, vals
			continue
		}
		if first && errors.Is(err, ebpf.ErrNotSupported) {
			return true, err
		}
		first = false
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i]) {
				return false, nil
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("walk %s: %w", m, err)
		}
	}
}

type walkBuf[K, V any] struct {
	keys []K
	vals []V
}

// Chunk buffers are pooled per key/value type: every poll walks ten maps,
// and fresh 100+ KiB buffers each time are pure GC load on a near-empty map.
var walkBufPools sync.Map // (*walkBuf[K, V])(nil) -> *sync.Pool

func walkBufPool[K, V any]() *sync.Pool {
	id := (*walkBuf[K, V])(nil)
	if p, ok := walkBufPools.Load(id); ok {
		return p.(*sync.Pool)
	}
	p, _ := walkBufPools.LoadOrStore(id, new(sync.Pool))
	return p.(*sync.Pool)
}

func getWalkBuf[K, V any](chunk int) *walkBuf[K, V] {
	if b, ok := walkBufPool[K, V]().Get().(*walkBuf[K, V]); ok && len(b.keys) >= chunk {
		return b
	}
	return &walkBuf[K, V]{keys: make([]K, chunk), vals: make([]V, chunk)}
}

func walkIter[K, V any](m walkMap, fn func(K, V) bool) error {
	var k K
	var v V
	it := m.iterate()
	for it.Next(&k, &v) {
		if !fn(k, v) {
			return nil
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", m, err)
	}
	return nil
}

// DeleteKeys deletes keys from m and calls onDeleted with the index of each
// key it removed. Keys that no longer exist are skipped and counted in
// missing; any other per-key failure is skipped too and the first one is
// returned after the remaining keys have been tried.
func DeleteKeys[K any](w *MapWalker, m *ebpf.Map, keys []K, onDeleted func(int)) (missing int, err error) {
	return deleteKeys(w, ciliumMap{m}, keys, onDeleted)
}

func deleteKeys[K any](w *MapWalker, m walkMap, keys []K, onDeleted func(int)) (int, error) {
	missing := 0
	var firstErr error
	note := func(err error) {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			missing++
		} else if firstErr == nil {
			firstErr = fmt.Errorf("delete from %s: %w", m, err)
		}
	}

	start := 0
	for start < len(keys) && !w.noBatch.Load() {
		end := min(start+w.chunk(), len(keys))
		n, err := m.BatchDelete(keys[start:end], nil)
		if err != nil && errors.Is(err, ebpf.ErrNotSupported) {
			w.fallBack(err)
			break
		}
		for i := start; i < start+n; i++ {
			onDeleted(i)
		}
		if err == nil {
			start = end
			continue
		}
		// The kernel stops at the first failing key and reports how many it
		// deleted before it; skip that key and carry on.
		note(err)
		start = min(start+n+1, end)
	}

	for i := start; i < len(keys); i++ {
		if err := m.Delete(&keys[i]); err != nil {
			note(err)
			continue
		}
		onDeleted(i)
	}
	return missing, firstErr
}
