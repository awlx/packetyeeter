package analyzer

import (
	"net"
	"testing"
)

func TestTrackHTTPErrorsCountsAny4xxAndConsecutive(t *testing.T) {
	a := &Analyzer{httpErrorWindows: make(map[string]*httpErrorWindow)}
	ip := net.ParseIP("192.0.2.40")

	// Mixed 200/400 should still accumulate 4xx volume while consecutive resets.
	var count4xx, consecutive int
	for i := 0; i < 10; i++ {
		_, _, count4xx, consecutive = a.trackHTTPErrors(ip, 400, "/dns-query")
		_, _, count4xx, consecutive = a.trackHTTPErrors(ip, 200, "/dns-query")
	}
	if count4xx != 10 {
		t.Fatalf("count4xx after interleaved 400/200 = %d, want 10", count4xx)
	}
	if consecutive != 0 {
		t.Fatalf("consecutive after trailing 200 = %d, want 0", consecutive)
	}

	// Pure 400 streak builds consecutive.
	for i := 0; i < 15; i++ {
		_, _, count4xx, consecutive = a.trackHTTPErrors(ip, 400, "/dns-query")
	}
	if consecutive < 15 {
		t.Fatalf("consecutive pure 400 streak = %d, want >= 15", consecutive)
	}
	if count4xx < 20 {
		t.Fatalf("count4xx = %d, want >= 20 after streak", count4xx)
	}
}
