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
	histories    map[string]*EventHistory
	maxEvents    int
	maxAge       time.Duration
	cleanupInt   time.Duration
	lastCleanup  time.Time
	maxHistories int
}

// NewHistoryManager creates a new history manager
func NewHistoryManager(maxEvents int, maxAge time.Duration, cleanupInterval time.Duration) *HistoryManager {
	return &HistoryManager{
		histories:    make(map[string]*EventHistory),
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

	// Get or create history
	history, exists := hm.histories[ip]
	if !exists {
		if len(hm.histories) >= hm.maxHistories {
			hm.mu.Unlock()
			return
		}
		history = NewEventHistory(hm.maxEvents, hm.maxAge)
		hm.histories[ip] = history
	}
	shouldCleanup := now.Sub(hm.lastCleanup) > hm.cleanupInt
	if shouldCleanup {
		hm.lastCleanup = now
	}

	// Keep the manager lock until lastSeen is updated so cleanup cannot detach
	// a history while an event is being added to it.
	history.AddEvent(event)
	hm.mu.Unlock()

	// Periodic cleanup of expired histories
	if shouldCleanup {
		hm.Cleanup(now)
	}
}

// GetHistory returns event history for an IP
func (hm *HistoryManager) GetHistory(ip string) (*EventHistory, bool) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	history, exists := hm.histories[ip]
	return history, exists
}

// Cleanup removes histories for IPs with no recent activity.
func (hm *HistoryManager) Cleanup(now time.Time) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	cutoff := now.Add(-hm.maxAge)

	for ip, history := range hm.histories {
		history.mu.RLock()
		lastSeen := history.lastSeen
		history.mu.RUnlock()

		if lastSeen.Before(cutoff) {
			delete(hm.histories, ip)
		}
	}

	hm.lastCleanup = now
}

// Count returns number of tracked IPs
func (hm *HistoryManager) Count() int {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return len(hm.histories)
}
