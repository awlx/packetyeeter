package mapcleaner

import (
	"slices"
	"time"
)

// TimeTracker is an interface for any struct that tracks when it was last seen
type TimeTracker interface {
	GetLastSeen() time.Time
}

// RemoveOldestEntry removes the oldest entry from a map based on LastSeen timestamp.
// This is a generic helper for preventing unbounded map growth.
//
// Usage:
//
//	if len(myMap) > maxSize {
//	    RemoveOldestEntry(myMap, func(key string, value *MyStruct) time.Time {
//	        return value.LastSeen
//	    })
//	}
func RemoveOldestEntry[K comparable, V any](m map[K]V, getTimestamp func(K, V) time.Time) {
	if len(m) == 0 {
		return
	}

	var oldestKey K
	var oldestTime time.Time
	first := true

	for key, value := range m {
		timestamp := getTimestamp(key, value)
		if first || timestamp.Before(oldestTime) {
			oldestTime = timestamp
			oldestKey = key
			first = false
		}
	}

	if !first {
		delete(m, oldestKey)
	}
}

// RemoveOldestN removes the n oldest entries in a single pass. Callers that
// insert one entry at a time should evict a batch once over their cap instead
// of calling RemoveOldestEntry per insert: at a 10k-entry cap a per-insert
// full-map scan turns every new key into O(10k) work under the caller's lock,
// which a spoofed-source flood pays per packet.
//
// To cap a map's size on a hot insert path, prefer EnforceMaxSizeBatch, which
// owns the headroom policy rather than open-coding the batch size at each site.
func RemoveOldestN[K comparable, V any](m map[K]V, n int, getTimestamp func(K, V) time.Time) {
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
	slices.SortFunc(entries, func(a, b entry) int {
		return a.ts.Compare(b.ts)
	})
	for i := range n {
		delete(m, entries[i].key)
	}
}

// RemoveEntriesOlderThan removes all entries from a map that are older than the cutoff time.
// This is useful for periodic cleanup of stale entries.
//
// Usage:
//
//	now := time.Now()
//	cutoff := now.Add(-1 * time.Hour)
//	RemoveEntriesOlderThan(myMap, cutoff, func(key string, value *MyStruct) time.Time {
//	    return value.LastObservedAt
//	})
func RemoveEntriesOlderThan[K comparable, V any](m map[K]V, cutoff time.Time, getTimestamp func(K, V) time.Time) int {
	removed := 0
	for key, value := range m {
		if getTimestamp(key, value).Before(cutoff) {
			delete(m, key)
			removed++
		}
	}
	return removed
}

// EnforceMaxSize ensures a map doesn't exceed maxSize by removing oldest entries.
// This is a convenience wrapper that combines size checking and cleanup.
//
// Usage:
//
//	EnforceMaxSize(myMap, 10000, func(key string, value *MyStruct) time.Time {
//	    return value.LastSeen
//	})
func EnforceMaxSize[K comparable, V any](m map[K]V, maxSize int, getTimestamp func(K, V) time.Time) {
	for len(m) > maxSize {
		RemoveOldestEntry(m, getTimestamp)
	}
}

// batchEvictHeadroom divides maxSize to decide how much slack
// EnforceMaxSizeBatch leaves below the cap: it removes the overflow plus
// maxSize/batchEvictHeadroom extra entries, so the O(n) oldest-scan runs once
// per ~that many inserts once the map is full, instead of on every insert.
const batchEvictHeadroom = 10

// EnforceMaxSizeBatch keeps m at or below maxSize while amortizing the cost of
// locating the oldest entries. When m exceeds maxSize it removes, in a single
// sorted pass, the overflow plus a maxSize/batchEvictHeadroom headroom margin,
// so a caller on a hot insert path pays the O(n) scan once per batch rather
// than on every insert (unlike EnforceMaxSize, which evicts one-at-a-time).
// Prefer this on paths that insert under load — per-signal or per-packet caches
// that a spoofed-source flood drives to the cap. getTimestamp orders entries
// oldest-first.
func EnforceMaxSizeBatch[K comparable, V any](m map[K]V, maxSize int, getTimestamp func(K, V) time.Time) {
	if maxSize <= 0 || len(m) <= maxSize {
		return
	}
	RemoveOldestN(m, len(m)-maxSize+maxSize/batchEvictHeadroom, getTimestamp)
}
