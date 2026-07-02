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
	events      []SignalEvent // Ring buffer of events
	paths       []string      // Recent paths accessed
	userAgents  []string      // Recent User-Agents
	methods     []string      // HTTP methods
	referers    []string      // Referer headers
	acceptLangs []string      // Accept-Language headers
	timestamps  []time.Time   // Event timestamps
	oldestIdx   int           // Ring buffer index
	size        int           // Current number of events stored
	created     time.Time     // When this history was created
	lastCleanup time.Time     // Last cleanup time
}

// NewEventHistory creates a new event history tracker
func NewEventHistory(maxEvents int, maxAge time.Duration) *EventHistory {
	now := time.Now()
	return &EventHistory{
		maxEvents:   maxEvents,
		maxAge:      maxAge,
		events:      make([]SignalEvent, maxEvents),
		paths:       make([]string, 0, maxEvents),
		userAgents:  make([]string, 0, maxEvents),
		methods:     make([]string, 0, maxEvents),
		referers:    make([]string, 0, maxEvents),
		acceptLangs: make([]string, 0, maxEvents),
		timestamps:  make([]time.Time, 0, maxEvents),
		created:     now,
		lastCleanup: now,
	}
}

// AddEvent adds an event to the history with automatic cleanup
func (h *EventHistory) AddEvent(event SignalEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()

	// Periodic cleanup (every 5 seconds)
	if now.Sub(h.lastCleanup) > 5*time.Second {
		h.cleanupOldEventsLocked(now)
		h.lastCleanup = now
	}

	// Add event to ring buffer
	if h.size < h.maxEvents {
		// Still filling up
		idx := h.size
		h.events[idx] = event
		h.timestamps = append(h.timestamps, now)
		h.size++
	} else {
		// Ring buffer is full, overwrite oldest
		h.events[h.oldestIdx] = event
		h.timestamps[h.oldestIdx] = now
		h.oldestIdx = (h.oldestIdx + 1) % h.maxEvents
	}

	// Extract metadata for feature computation
	if event.Metadata != nil {
		if path, ok := event.Metadata["path"].(string); ok && path != "" {
			h.paths = append(h.paths, path)
			if len(h.paths) > h.maxEvents {
				h.paths = h.paths[1:]
			}
		}
		if ua, ok := event.Metadata["user_agent"].(string); ok && ua != "" {
			h.userAgents = append(h.userAgents, ua)
			if len(h.userAgents) > h.maxEvents {
				h.userAgents = h.userAgents[1:]
			}
		}
		if method, ok := event.Metadata["method"].(string); ok && method != "" {
			h.methods = append(h.methods, method)
			if len(h.methods) > h.maxEvents {
				h.methods = h.methods[1:]
			}
		}
		if referer, ok := event.Metadata["referer"].(string); ok && referer != "" {
			h.referers = append(h.referers, referer)
			if len(h.referers) > h.maxEvents {
				h.referers = h.referers[1:]
			}
		}
		if acceptLang, ok := event.Metadata["accept_language"].(string); ok && acceptLang != "" {
			h.acceptLangs = append(h.acceptLangs, acceptLang)
			if len(h.acceptLangs) > h.maxEvents {
				h.acceptLangs = h.acceptLangs[1:]
			}
		}
	}
}

// cleanupOldEventsLocked removes events older than maxAge (must be called with lock held)
func (h *EventHistory) cleanupOldEventsLocked(now time.Time) {
	cutoff := now.Add(-h.maxAge)

	// Count how many events to remove from the front of ring buffer
	removeCount := 0
	for i := 0; i < h.size; i++ {
		// Check timestamp in ring buffer order, but timestamps slice uses sequential indexing
		if i < len(h.timestamps) && h.timestamps[i].Before(cutoff) {
			removeCount++
		} else {
			break
		}
	}

	if removeCount > 0 {
		h.oldestIdx = (h.oldestIdx + removeCount) % h.maxEvents
		h.size -= removeCount

		// Trim metadata slices (these are NOT ring buffers, just regular slices)
		if removeCount < len(h.timestamps) {
			h.timestamps = h.timestamps[removeCount:]
		} else {
			h.timestamps = h.timestamps[:0]
		}
		if removeCount < len(h.paths) {
			h.paths = h.paths[removeCount:]
		} else {
			h.paths = h.paths[:0]
		}
		if removeCount < len(h.userAgents) {
			h.userAgents = h.userAgents[removeCount:]
		} else {
			h.userAgents = h.userAgents[:0]
		}
		if removeCount < len(h.methods) {
			h.methods = h.methods[removeCount:]
		} else {
			h.methods = h.methods[:0]
		}
		if removeCount < len(h.referers) {
			h.referers = h.referers[removeCount:]
		} else {
			h.referers = h.referers[:0]
		}
		if removeCount < len(h.acceptLangs) {
			h.acceptLangs = h.acceptLangs[removeCount:]
		} else {
			h.acceptLangs = h.acceptLangs[:0]
		}
	}
}

// GetSnapshot returns a read-only snapshot of current events for feature extraction
func (h *EventHistory) GetSnapshot() EventHistorySnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	snapshot := EventHistorySnapshot{
		Events:      make([]SignalEvent, 0, h.size),
		Paths:       make([]string, len(h.paths)),
		UserAgents:  make([]string, len(h.userAgents)),
		Methods:     make([]string, len(h.methods)),
		Referers:    make([]string, len(h.referers)),
		AcceptLangs: make([]string, len(h.acceptLangs)),
		Timestamps:  make([]time.Time, 0, h.size),
	}

	// Copy events from ring buffer in order
	for i := 0; i < h.size; i++ {
		idx := (h.oldestIdx + i) % h.maxEvents
		snapshot.Events = append(snapshot.Events, h.events[idx])
		if idx < len(h.timestamps) {
			snapshot.Timestamps = append(snapshot.Timestamps, h.timestamps[idx])
		}
	}

	copy(snapshot.Paths, h.paths)
	copy(snapshot.UserAgents, h.userAgents)
	copy(snapshot.Methods, h.methods)
	copy(snapshot.Referers, h.referers)
	copy(snapshot.AcceptLangs, h.acceptLangs)

	return snapshot
}

// Size returns current number of events stored
func (h *EventHistory) Size() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.size
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
	mu          sync.RWMutex
	histories   map[string]*EventHistory
	maxEvents   int
	maxAge      time.Duration
	cleanupInt  time.Duration
	lastCleanup time.Time
}

// NewHistoryManager creates a new history manager
func NewHistoryManager(maxEvents int, maxAge time.Duration, cleanupInterval time.Duration) *HistoryManager {
	return &HistoryManager{
		histories:   make(map[string]*EventHistory),
		maxEvents:   maxEvents,
		maxAge:      maxAge,
		cleanupInt:  cleanupInterval,
		lastCleanup: time.Now(),
	}
}

// AddEvent adds an event for an IP
func (hm *HistoryManager) AddEvent(ip string, event SignalEvent) {
	hm.mu.Lock()

	// Get or create history
	history, exists := hm.histories[ip]
	if !exists {
		history = NewEventHistory(hm.maxEvents, hm.maxAge)
		hm.histories[ip] = history
	}

	hm.mu.Unlock()

	// Add event (history has its own lock)
	history.AddEvent(event)

	// Periodic cleanup of expired histories
	now := time.Now()
	if now.Sub(hm.lastCleanup) > hm.cleanupInt {
		hm.cleanupExpiredHistories(now)
	}
}

// GetHistory returns event history for an IP
func (hm *HistoryManager) GetHistory(ip string) (*EventHistory, bool) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	history, exists := hm.histories[ip]
	return history, exists
}

// cleanupExpiredHistories removes histories for IPs with no recent activity
func (hm *HistoryManager) cleanupExpiredHistories(now time.Time) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	cutoff := now.Add(-hm.maxAge * 2) // Keep history for 2x maxAge

	for ip, history := range hm.histories {
		history.mu.RLock()
		created := history.created
		size := history.size
		history.mu.RUnlock()

		// Remove if old and empty
		if size == 0 && created.Before(cutoff) {
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
