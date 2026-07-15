package aidetection

import (
	"sync"
	"time"
)

// EventHistory maintains a sliding window of recent events for feature extraction
type EventHistory struct {
	mu          sync.RWMutex
	maxEvents   int
	maxAge      time.Duration
	events      []SignalEvent // Recent events in chronological order
	created     time.Time     // When this history was created
	lastSeen    time.Time
	lastCleanup time.Time // Last cleanup time
}

// NewEventHistory creates a new event history tracker
func NewEventHistory(maxEvents int, maxAge time.Duration) *EventHistory {
	now := time.Now()
	return &EventHistory{
		maxEvents:   maxEvents,
		maxAge:      maxAge,
		events:      make([]SignalEvent, 0, min(maxEvents, 8)),
		created:     now,
		lastSeen:    now,
		lastCleanup: now,
	}
}

// AddEvent adds an event to the history with automatic cleanup
func (h *EventHistory) AddEvent(event SignalEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	}

	// Periodic cleanup (every 5 seconds)
	if now.Sub(h.lastCleanup) > 5*time.Second {
		h.cleanupOldEventsLocked(now)
		h.lastCleanup = now
	}

	event.Metadata = cloneMetadata(event.Metadata, map[string]struct{}{
		"path": {}, "method": {}, "user_agent": {}, "referer": {},
		"accept_language": {}, "status_code": {}, "ja4": {}, "ja4h": {}, "ja4t": {},
	})
	if len(h.events) == h.maxEvents {
		copy(h.events, h.events[1:])
		h.events[len(h.events)-1] = event
	} else {
		h.events = append(h.events, event)
	}
	h.lastSeen = now
}

// cleanupOldEventsLocked removes events older than maxAge (must be called with lock held)
func (h *EventHistory) cleanupOldEventsLocked(now time.Time) {
	cutoff := now.Add(-h.maxAge)

	first := 0
	for first < len(h.events) && h.events[first].Timestamp.Before(cutoff) {
		first++
	}
	if first > 0 {
		copy(h.events, h.events[first:])
		h.events = h.events[:len(h.events)-first]
	}
}

// GetSnapshot returns a read-only snapshot of current events for feature extraction
func (h *EventHistory) GetSnapshot() EventHistorySnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	snapshot := EventHistorySnapshot{
		Events:     make([]SignalEvent, len(h.events)),
		Timestamps: make([]time.Time, 0, len(h.events)),
	}
	copy(snapshot.Events, h.events)
	for _, event := range h.events {
		snapshot.Timestamps = append(snapshot.Timestamps, event.Timestamp)
		if path, ok := event.Metadata["path"].(string); ok && path != "" {
			snapshot.Paths = append(snapshot.Paths, path)
		}
		if ua, ok := event.Metadata["user_agent"].(string); ok && ua != "" {
			snapshot.UserAgents = append(snapshot.UserAgents, ua)
		}
		if method, ok := event.Metadata["method"].(string); ok && method != "" {
			snapshot.Methods = append(snapshot.Methods, method)
		}
		if referer, ok := event.Metadata["referer"].(string); ok && referer != "" {
			snapshot.Referers = append(snapshot.Referers, referer)
		}
		if acceptLang, ok := event.Metadata["accept_language"].(string); ok && acceptLang != "" {
			snapshot.AcceptLangs = append(snapshot.AcceptLangs, acceptLang)
		}
	}

	return snapshot
}

// Size returns current number of events stored
func (h *EventHistory) Size() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.events)
}

// EventHistorySnapshot is an immutable snapshot of event history for feature extraction
type EventHistorySnapshot struct {
	Events      []SignalEvent
	Paths       []string
	UserAgents  []string
	Methods     []string
	Referers    []string
	AcceptLangs []string
	Timestamps  []time.Time
}

// HistoryManager manages event histories for all tracked IPs
type HistoryManager struct {
	mu           sync.RWMutex
	histories    map[string]*historyEntry
	maxEvents    int
	maxAge       time.Duration
	cleanupInt   time.Duration
	lastCleanup  time.Time
	maxHistories int
}

type historyEntry struct {
	history *EventHistory
	active  int
	// generation prevents cleanup from acting on an expiry observation made before an add completed.
	generation uint64
}

type historyCandidate struct {
	ip         string
	entry      *historyEntry
	active     int
	generation uint64
}

// NewHistoryManager creates a new history manager
func NewHistoryManager(maxEvents int, maxAge time.Duration, cleanupInterval time.Duration) *HistoryManager {
	return &HistoryManager{
		histories:    make(map[string]*historyEntry),
		maxEvents:    maxEvents,
		maxAge:       maxAge,
		cleanupInt:   cleanupInterval,
		lastCleanup:  time.Now(),
		maxHistories: 20000,
	}
}

// AddEvent adds an event for an IP
func (hm *HistoryManager) AddEvent(ip string, event SignalEvent) {
	now := time.Now()
	hm.mu.Lock()

	entry, exists := hm.histories[ip]
	if !exists {
		if len(hm.histories) >= hm.maxHistories {
			hm.mu.Unlock()
			return
		}
		entry = &historyEntry{history: NewEventHistory(hm.maxEvents, hm.maxAge)}
		hm.histories[ip] = entry
	}
	entry.active++
	shouldCleanup := now.Sub(hm.lastCleanup) > hm.cleanupInt
	if shouldCleanup {
		hm.lastCleanup = now
	}
	hm.mu.Unlock()

	func() {
		defer hm.finishAdd(entry)
		entry.history.AddEvent(event)
	}()

	// Periodic cleanup of expired histories
	if shouldCleanup {
		hm.Cleanup(now)
	}
}

func (hm *HistoryManager) finishAdd(entry *historyEntry) {
	hm.mu.Lock()
	entry.generation++
	entry.active--
	hm.mu.Unlock()
}

// GetHistory returns event history for an IP
func (hm *HistoryManager) GetHistory(ip string) (*EventHistory, bool) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	entry, exists := hm.histories[ip]
	if !exists {
		return nil, false
	}
	return entry.history, true
}

// Cleanup removes histories for IPs with no recent activity.
func (hm *HistoryManager) Cleanup(now time.Time) {
	cutoff := now.Add(-hm.maxAge)

	hm.mu.RLock()
	candidates := make([]historyCandidate, 0, len(hm.histories))
	for ip, entry := range hm.histories {
		candidates = append(candidates, historyCandidate{
			ip:         ip,
			entry:      entry,
			active:     entry.active,
			generation: entry.generation,
		})
	}
	hm.mu.RUnlock()

	for _, candidate := range candidates {
		if candidate.active > 0 {
			continue
		}
		candidate.entry.history.mu.RLock()
		expired := candidate.entry.history.lastSeen.Before(cutoff)
		candidate.entry.history.mu.RUnlock()
		if !expired {
			continue
		}
		hm.deleteExpired(candidate)
	}

	hm.mu.Lock()
	hm.lastCleanup = now
	hm.mu.Unlock()
}

func (hm *HistoryManager) deleteExpired(candidate historyCandidate) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	current, exists := hm.histories[candidate.ip]
	if exists &&
		current == candidate.entry &&
		current.active == 0 &&
		current.generation == candidate.generation {
		delete(hm.histories, candidate.ip)
	}
}

// Count returns number of tracked IPs
func (hm *HistoryManager) Count() int {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return len(hm.histories)
}
