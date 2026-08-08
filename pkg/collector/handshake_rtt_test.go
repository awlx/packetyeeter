package collector

import "testing"

// A pending handshake with no SYN-ACK observed has SynAckTime==0; the unsigned
// subtraction SynAckTime-BeginTime then underflows into a huge value that, cast
// to int64, poisons the aggregated RTT. handshakeRTTNanos must reject it.
func TestHandshakeRTTNanos(t *testing.T) {
	if rtt, ok := handshakeRTTNanos(5_000_000_100, 5_000_000_000); !ok || rtt != 100 {
		t.Fatalf("completed handshake: got (%d,%v), want (100,true)", rtt, ok)
	}
	if _, ok := handshakeRTTNanos(0, 5_000_000_000); ok {
		t.Fatal("incomplete handshake (synAckTime=0) must be invalid, not underflow")
	}
	if _, ok := handshakeRTTNanos(100, 100); ok {
		t.Fatal("equal timestamps must be invalid (no positive RTT)")
	}
}

func TestAvgRTTNanos(t *testing.T) {
	if got := avgRTTNanos(300, 3); got != 100 {
		t.Fatalf("avg = %d, want 100", got)
	}
	if got := avgRTTNanos(0, 0); got != 0 {
		t.Fatalf("no valid RTTs must yield 0 (no divide-by-zero), got %d", got)
	}
}
