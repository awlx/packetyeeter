package analyzer

import (
	"fmt"
	"net"
	"testing"
)

// Exceeding maxEvents must trim the window down to the cap, not flush it
// entirely. With the old prune condition (len(events) <= maxEvents, ignoring
// the prune index), event maxEvents+1 discarded the whole buffer and reset the
// scanner-detection tallies to zero.

func TestTrackHTTPErrorsCapKeepsWindow(t *testing.T) {
	a := &Analyzer{httpErrorWindows: make(map[string]*httpErrorWindow)}
	ip := net.ParseIP("192.0.2.1")

	var count404 int
	for i := 0; i < 101; i++ {
		count404, _, _ = a.trackHTTPErrors(ip, 404, fmt.Sprintf("/probe/%d", i))
	}
	if count404 != 100 {
		t.Fatalf("count404 after 101 events = %d, want 100 (window flushed instead of trimmed)", count404)
	}
	if got := len(a.httpErrorWindows[ip.String()].Events); got != 100 {
		t.Fatalf("retained events = %d, want 100", got)
	}
}

func TestUpdatePathEntropyCapKeepsWindow(t *testing.T) {
	a := &Analyzer{pathWindows: make(map[string]*pathWindow)}
	ip := net.ParseIP("192.0.2.2")

	var unique int
	for i := 0; i < 201; i++ {
		_, _, _, unique, _, _ = a.updatePathEntropy(ip, fmt.Sprintf("/path/%d", i))
	}
	if unique != 200 {
		t.Fatalf("unique paths after 201 events = %d, want 200 (window flushed instead of trimmed)", unique)
	}
	if got := len(a.pathWindows[ip.String()].Events); got != 200 {
		t.Fatalf("retained events = %d, want 200", got)
	}
}
