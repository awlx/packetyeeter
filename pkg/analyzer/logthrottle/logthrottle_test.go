package logthrottle

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func TestAllowFiresOncePerIPPerInterval(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	throttle := New(30*time.Second, 100, clock.Now)
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")

	if !throttle.Allow(first) {
		t.Fatal("first call for an IP must log")
	}
	for range 5 {
		if throttle.Allow(first) {
			t.Fatal("repeat call inside the interval must not log")
		}
	}
	if !throttle.Allow(second) {
		t.Fatal("a different IP must log independently")
	}

	clock.now = clock.now.Add(29 * time.Second)
	if throttle.Allow(first) {
		t.Fatal("call before the interval ends must not log")
	}
	clock.now = clock.now.Add(time.Second)
	if !throttle.Allow(first) {
		t.Fatal("call after the interval must log again")
	}
	if throttle.Allow(first) {
		t.Fatal("second call in the new interval must not log")
	}
}

func TestAllowIPTreatsMappedIPv4AsIPv4(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	throttle := New(30*time.Second, 100, clock.Now)
	if !throttle.AllowIP(net.ParseIP("192.0.2.1")) {
		t.Fatal("first call must log")
	}
	if throttle.AllowIP(net.ParseIP("192.0.2.1").To4()) {
		t.Fatal("4-byte and 16-byte forms of one IPv4 address must share a key")
	}
}

func TestAllowBoundsTrackedKeys(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	throttle := New(30*time.Second, 2, clock.Now)
	throttle.Allow(netip.MustParseAddr("192.0.2.1"))
	throttle.Allow(netip.MustParseAddr("192.0.2.2"))
	throttle.Allow(netip.MustParseAddr("192.0.2.3"))
	if got := len(throttle.lastLogged); got != 2 {
		t.Fatalf("tracked keys = %d, want 2", got)
	}

	clock.now = clock.now.Add(30 * time.Second)
	if !throttle.Allow(netip.MustParseAddr("192.0.2.4")) {
		t.Fatal("a new IP must log after expired entries are swept")
	}
	if got := len(throttle.lastLogged); got != 1 {
		t.Fatalf("tracked keys after sweep = %d, want 1", got)
	}
}

func TestAllowFullTableFallsBackToGlobalRate(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	throttle := New(30*time.Second, DefaultMaxKeys, clock.Now)
	for i := range DefaultMaxKeys {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		if !throttle.Allow(addr) {
			t.Fatalf("IP %d must log while the table has room", i)
		}
	}

	newIP := func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{172, 16, byte(i >> 8), byte(i)})
	}
	next := 0
	logged := func(calls int) int {
		count := 0
		for range calls {
			if throttle.Allow(newIP(next)) {
				count++
			}
			next++
		}
		return count
	}

	if got := logged(100); got != OverflowLinesPerSecond {
		t.Fatalf("new IPs logged with a full table = %d, want %d", got, OverflowLinesPerSecond)
	}
	clock.now = clock.now.Add(999 * time.Millisecond)
	if got := logged(100); got != 0 {
		t.Fatalf("new IPs logged before one second passed = %d, want 0", got)
	}
	for second := range 5 {
		clock.now = clock.now.Add(time.Second)
		if got := logged(100); got != OverflowLinesPerSecond {
			t.Fatalf("second %d: new IPs logged = %d, want %d", second, got, OverflowLinesPerSecond)
		}
	}
	if got := len(throttle.lastLogged); got != DefaultMaxKeys {
		t.Fatalf("tracked keys = %d, want %d", got, DefaultMaxKeys)
	}
}
