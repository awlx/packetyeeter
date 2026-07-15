package aidetection

import (
	"testing"
	"time"
)

func TestHistoryManagerCleanupDoesNotDetachActiveAdd(t *testing.T) {
	hm := NewHistoryManager(8, time.Minute, time.Hour)
	const ip = "192.0.2.1"
	hm.AddEvent(ip, SignalEvent{Type: SignalTCPMetadata})

	history, ok := hm.GetHistory(ip)
	if !ok {
		t.Fatal("expected history")
	}
	history.mu.Lock()
	history.lastSeen = time.Now().Add(-2 * time.Minute)

	addDone := make(chan struct{})
	go func() {
		hm.AddEvent(ip, SignalEvent{Type: SignalBrowserDetected})
		close(addDone)
	}()
	waitForActiveAdds(t, hm, ip, 1)

	cleanupDone := make(chan struct{})
	go func() {
		hm.Cleanup(time.Now())
		close(cleanupDone)
	}()

	countDone := make(chan int, 1)
	go func() {
		countDone <- hm.Count()
	}()
	select {
	case count := <-countDone:
		if count != 1 {
			t.Fatalf("Count() = %d while add active, want 1", count)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup held the manager lock while waiting for a history")
	}

	hm.mu.RLock()
	entry := hm.histories[ip]
	if entry == nil || entry.history != history || entry.active != 1 {
		hm.mu.RUnlock()
		t.Fatal("cleanup detached a history with an active add")
	}
	hm.mu.RUnlock()

	history.mu.Unlock()
	waitForDone(t, addDone, "add")
	waitForDone(t, cleanupDone, "cleanup")

	current, ok := hm.GetHistory(ip)
	if !ok || current != history {
		t.Fatal("active history was detached during cleanup")
	}
	if size := current.Size(); size != 2 {
		t.Fatalf("history contains %d events after concurrent cleanup, want 2", size)
	}

	hm.Cleanup(time.Now().Add(2 * time.Minute))
	if count := hm.Count(); count != 0 {
		t.Fatalf("Count() = %d after history expired, want 0", count)
	}
}

func TestHistoryManagerDifferentHistoriesAddConcurrently(t *testing.T) {
	hm := NewHistoryManager(8, time.Minute, time.Hour)
	const blockedIP = "192.0.2.1"
	const independentIP = "192.0.2.2"
	hm.AddEvent(blockedIP, SignalEvent{Type: SignalTCPMetadata})
	hm.AddEvent(independentIP, SignalEvent{Type: SignalTCPMetadata})

	blockedHistory, ok := hm.GetHistory(blockedIP)
	if !ok {
		t.Fatal("expected blocked history")
	}
	blockedHistory.mu.Lock()

	blockedDone := make(chan struct{})
	go func() {
		hm.AddEvent(blockedIP, SignalEvent{Type: SignalBrowserDetected})
		close(blockedDone)
	}()
	waitForActiveAdds(t, hm, blockedIP, 1)

	independentDone := make(chan struct{})
	go func() {
		hm.AddEvent(independentIP, SignalEvent{Type: SignalBrowserDetected})
		close(independentDone)
	}()
	select {
	case <-independentDone:
	case <-time.After(time.Second):
		blockedHistory.mu.Unlock()
		t.Fatal("add to a different history was serialized behind the blocked history")
	}

	blockedHistory.mu.Unlock()
	waitForDone(t, blockedDone, "blocked add")

	independentHistory, ok := hm.GetHistory(independentIP)
	if !ok {
		t.Fatal("expected independent history")
	}
	if size := independentHistory.Size(); size != 2 {
		t.Fatalf("independent history contains %d events, want 2", size)
	}
}

func TestHistoryManagerCleanupCandidateCannotDeleteCompletedAdd(t *testing.T) {
	hm := NewHistoryManager(8, time.Minute, time.Hour)
	const ip = "192.0.2.1"
	hm.AddEvent(ip, SignalEvent{Type: SignalTCPMetadata})

	hm.mu.RLock()
	entry := hm.histories[ip]
	candidate := historyCandidate{
		ip:         ip,
		entry:      entry,
		generation: entry.generation,
	}
	hm.mu.RUnlock()

	entry.history.mu.Lock()
	entry.history.lastSeen = time.Now().Add(-2 * time.Minute)
	entry.history.mu.Unlock()

	addDone := make(chan struct{})
	go func() {
		hm.AddEvent(ip, SignalEvent{Type: SignalBrowserDetected})
		close(addDone)
	}()
	waitForDone(t, addDone, "add")

	hm.deleteExpired(candidate)

	current, ok := hm.GetHistory(ip)
	if !ok || current != entry.history {
		t.Fatal("stale cleanup candidate detached a history after an add completed")
	}
	if size := current.Size(); size != 2 {
		t.Fatalf("history contains %d events after stale cleanup candidate, want 2", size)
	}
}

func TestHistoryManagerCleanupCandidateCannotDeleteReplacement(t *testing.T) {
	hm := NewHistoryManager(8, time.Minute, time.Hour)
	const ip = "192.0.2.1"
	hm.AddEvent(ip, SignalEvent{Type: SignalTCPMetadata})

	hm.mu.Lock()
	oldEntry := hm.histories[ip]
	candidate := historyCandidate{
		ip:         ip,
		entry:      oldEntry,
		generation: oldEntry.generation,
	}
	delete(hm.histories, ip)
	hm.mu.Unlock()

	hm.AddEvent(ip, SignalEvent{Type: SignalBrowserDetected})
	hm.deleteExpired(candidate)

	current, ok := hm.GetHistory(ip)
	if !ok || current == oldEntry.history {
		t.Fatal("stale cleanup candidate deleted the replacement history")
	}
	if size := current.Size(); size != 1 {
		t.Fatalf("replacement history contains %d events, want 1", size)
	}
}

func waitForActiveAdds(t *testing.T, hm *HistoryManager, ip string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		hm.mu.RLock()
		entry := hm.histories[ip]
		active := 0
		if entry != nil {
			active = entry.active
		}
		hm.mu.RUnlock()
		if active == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active adds for %s = %d, want %d", ip, active, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForDone(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s did not complete", operation)
	}
}
