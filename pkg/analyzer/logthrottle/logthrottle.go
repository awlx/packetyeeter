package logthrottle

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	DefaultInterval = 30 * time.Second
	DefaultMaxKeys  = 20000

	OverflowLinesPerSecond = 1
	overflowInterval       = time.Second / OverflowLinesPerSecond
)

type Throttle struct {
	mu         sync.Mutex
	now        func() time.Time
	interval   time.Duration
	maxKeys    int
	lastLogged map[netip.Addr]time.Time
	lastSweep  time.Time

	lastOverflow time.Time
}

func New(interval time.Duration, maxKeys int, now func() time.Time) *Throttle {
	return &Throttle{
		now:        now,
		interval:   max(interval, time.Second),
		maxKeys:    max(maxKeys, 1),
		lastLogged: make(map[netip.Addr]time.Time),
	}
}

func NewDefault() *Throttle {
	return New(DefaultInterval, DefaultMaxKeys, time.Now)
}

func (t *Throttle) AllowIP(ip net.IP) bool {
	addr, _ := netip.AddrFromSlice(ip)
	return t.Allow(addr.Unmap())
}

func (t *Throttle) Allow(addr netip.Addr) bool {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if prev, ok := t.lastLogged[addr]; ok {
		if now.Sub(prev) < t.interval {
			return false
		}
		t.lastLogged[addr] = now
		return true
	}
	if len(t.lastLogged) >= t.maxKeys {
		t.sweepExpiredLocked(now)
		if len(t.lastLogged) >= t.maxKeys {
			return t.allowOverflowLocked(now)
		}
	}
	t.lastLogged[addr] = now
	return true
}

func (t *Throttle) sweepExpiredLocked(now time.Time) {
	if now.Sub(t.lastSweep) < t.interval {
		return
	}
	t.lastSweep = now
	for addr, logged := range t.lastLogged {
		if now.Sub(logged) >= t.interval {
			delete(t.lastLogged, addr)
		}
	}
}

func (t *Throttle) allowOverflowLocked(now time.Time) bool {
	if !t.lastOverflow.IsZero() && now.Sub(t.lastOverflow) < overflowInterval {
		return false
	}
	t.lastOverflow = now
	return true
}
