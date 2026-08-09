package collector

import (
	"testing"
	"time"
)

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

func TestPendingHandshakeExpired(t *testing.T) {
	now := uint64(30 * time.Second)
	timeout := uint64(pendingHandshakeTimeout)

	tests := []struct {
		name    string
		beginNS uint64
		want    bool
	}{
		{name: "active", beginNS: now - timeout + 1, want: false},
		{name: "at timeout", beginNS: now - timeout, want: true},
		{name: "expired", beginNS: now - timeout - 1, want: true},
		{name: "missing timestamp", beginNS: 0, want: false},
		{name: "future timestamp", beginNS: now + 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pendingHandshakeExpired(now, tt.beginNS); got != tt.want {
				t.Fatalf("pendingHandshakeExpired(%d, %d) = %v, want %v", now, tt.beginNS, got, tt.want)
			}
		})
	}
}

func TestPendingHandshakeRateUsesPollInterval(t *testing.T) {
	if got := pendingHandshakeRate(0, time.Second); got != 0 {
		t.Fatalf("empty batch rate = %v, want 0", got)
	}
	if got := pendingHandshakeRate(6, time.Second); got != 6 {
		t.Fatalf("six handshakes over one second = %v pps, want 6", got)
	}
	if got := pendingHandshakeRate(6, 200*time.Millisecond); got != 30 {
		t.Fatalf("six handshakes over 200ms = %v pps, want 30", got)
	}
	if got := pendingHandshakeRate(6, 0); got != 6 {
		t.Fatalf("zero interval must use the one-second poll default, got %v pps", got)
	}
}
