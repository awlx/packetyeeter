package aidetection

import (
	"testing"
	"time"
)

func TestHistoryManagerDifferentIPsDoNotSerialize(t *testing.T) {
	manager := NewHistoryManager(10, time.Minute, time.Hour)
	manager.AddEvent("blocked", SignalEvent{Timestamp: time.Now()})

	blockedHistory, ok := manager.GetHistory("blocked")
	if !ok {
		t.Fatal("blocked history was not created")
	}
	blockedHistory.mu.Lock()

	blockedDone := make(chan struct{})
	go func() {
		manager.AddEvent("blocked", SignalEvent{Timestamp: time.Now()})
		close(blockedDone)
	}()
	waitForActiveHistoryAdd(t, manager, "blocked")

	otherDone := make(chan struct{})
	go func() {
		manager.AddEvent("other", SignalEvent{Timestamp: time.Now()})
		close(otherDone)
	}()

	select {
	case <-otherDone:
	case <-time.After(time.Second):
		blockedHistory.mu.Unlock()
		t.Fatal("event for a different IP was serialized behind a blocked history")
	}

	blockedHistory.mu.Unlock()
	select {
	case <-blockedDone:
	case <-time.After(time.Second):
		t.Fatal("blocked history add did not complete")
	}
}

func TestHistoryManagerCleanupDoesNotDetachActiveAdd(t *testing.T) {
	manager := NewHistoryManager(10, time.Minute, time.Hour)
	manager.AddEvent("active", SignalEvent{Timestamp: time.Now().Add(-2 * time.Minute)})

	history, ok := manager.GetHistory("active")
	if !ok {
		t.Fatal("active history was not created")
	}
	history.mu.Lock()
	history.lastSeen = time.Now().Add(-2 * time.Minute)

	addDone := make(chan struct{})
	go func() {
		manager.AddEvent("active", SignalEvent{Timestamp: time.Now()})
		close(addDone)
	}()
	waitForActiveHistoryAdd(t, manager, "active")

	manager.Cleanup(time.Now())
	retained, ok := manager.GetHistory("active")
	if !ok || retained != history {
		history.mu.Unlock()
		t.Fatal("cleanup detached a history with an active add")
	}

	history.mu.Unlock()
	select {
	case <-addDone:
	case <-time.After(time.Second):
		t.Fatal("active history add did not complete")
	}

	manager.Cleanup(time.Now())
	retained, ok = manager.GetHistory("active")
	if !ok || retained != history {
		t.Fatal("cleanup detached history after its active add refreshed lastSeen")
	}
	if got := retained.Size(); got != 2 {
		t.Fatalf("history retained %d events, want 2", got)
	}
}

func waitForActiveHistoryAdd(t *testing.T, manager *HistoryManager, ip string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		manager.mu.RLock()
		active := manager.activeAdds[ip]
		manager.mu.RUnlock()
		if active > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("history add for %q did not become active", ip)
		}
		time.Sleep(time.Millisecond)
	}
}
