package mapcleaner

import (
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
