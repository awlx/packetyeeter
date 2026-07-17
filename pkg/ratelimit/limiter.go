package ratelimit

import (
	"net"
	"sync"
	"time"
)

const (
	// UnknownASN is the sentinel value pkg/geoip.LookupWithDefaults returns
	// when a source IP's ASN cannot be resolved (private ranges, unlisted
	// allocations, or attacker-chosen unresolved IPs). It must never be used
	// as a rate-limit bucket key: doing so would let every unrelated
	// unresolved-ASN client share one bucket that a single attacker can drain.
	UnknownASN = "Unknown"

	// defaultMaxIPLimiters bounds ipLimiters so a distinct-source-IP flood
	// cannot grow the map unbounded between cleanup passes.
	defaultMaxIPLimiters = 200000

	// defaultMaxASNLimiters bounds asnLimiters. Real-world ASN cardinality is
	// far below this; the cap only guards against pathological/attacker input.
	defaultMaxASNLimiters = 50000
)

// TokenBucket implements a token bucket rate limiter
type TokenBucket struct {
	mu sync.Mutex

	capacity float64 // Maximum tokens
	tokens   float64 // Current tokens
	rate     float64 // Tokens per second
	lastSeen time.Time
}

// NewTokenBucket creates a new token bucket rate limiter
func NewTokenBucket(capacity, rate float64) *TokenBucket {
	return &TokenBucket{
		capacity: capacity,
		tokens:   capacity,
		rate:     rate,
		lastSeen: time.Now(),
	}
}

// Allow checks if a request is allowed
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastSeen).Seconds()
	tb.lastSeen = now

	// Refill tokens based on elapsed time
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	// Try to consume a token
	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}

	return false
}

// setRate updates the bucket's refill rate and capacity in place, clamping
// any currently held tokens to the new capacity so a lowered limit takes
// effect immediately instead of only after the existing burst drains.
func (tb *TokenBucket) setRate(rate, capacity float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.rate = rate
	tb.capacity = capacity
	if tb.tokens > capacity {
		tb.tokens = capacity
	}
}

// Limiter manages rate limiting for IPs and ASNs
type Limiter struct {
	mu sync.RWMutex

	ipLimiters  map[string]*TokenBucket
	asnLimiters map[string]*TokenBucket

	ipRate  float64 // Requests per second per IP
	asnRate float64 // Requests per second per ASN

	ipBurst  float64 // Burst capacity per IP
	asnBurst float64 // Burst capacity per ASN

	maxIPLimiters  int // Hard cap on tracked per-IP limiters
	maxASNLimiters int // Hard cap on tracked per-ASN limiters

	// Cleanup
	cleanupInterval time.Duration
	maxAge          time.Duration
	lastCleanup     time.Time
}

// Config holds configuration for the rate limiter
type Config struct {
	IPRate          float64       // Requests per second per IP (default: 100)
	ASNRate         float64       // Requests per second per ASN (default: 1000)
	IPBurst         float64       // Burst capacity per IP (default: 200)
	ASNBurst        float64       // Burst capacity per ASN (default: 2000)
	CleanupInterval time.Duration // How often to clean up old limiters (default: 5min)
	MaxAge          time.Duration // How long to keep unused limiters (default: 10min)
	MaxIPEntries    int           // Hard cap on tracked per-IP limiters (default: 200000)
	MaxASNEntries   int           // Hard cap on tracked per-ASN limiters (default: 50000)
}

// DefaultConfig returns sensible rate limit defaults
func DefaultConfig() Config {
	return Config{
		IPRate:          100,  // 100 req/s per IP
		ASNRate:         1000, // 1000 req/s per ASN
		IPBurst:         200,  // 200 req burst per IP
		ASNBurst:        2000, // 2000 req burst per ASN
		CleanupInterval: 5 * time.Minute,
		MaxAge:          10 * time.Minute,
		MaxIPEntries:    defaultMaxIPLimiters,
		MaxASNEntries:   defaultMaxASNLimiters,
	}
}

// NewLimiter creates a new rate limiter
func NewLimiter(cfg Config) *Limiter {
	// Default each field independently: the old all-or-nothing IPRate==0
	// check let a partial config reach cleanupLoop with CleanupInterval==0,
	// where time.NewTicker(0) panics on a background goroutine.
	defaults := DefaultConfig()
	if cfg.IPRate <= 0 {
		cfg.IPRate = defaults.IPRate
	}
	if cfg.ASNRate <= 0 {
		cfg.ASNRate = defaults.ASNRate
	}
	if cfg.IPBurst <= 0 {
		cfg.IPBurst = defaults.IPBurst
	}
	if cfg.ASNBurst <= 0 {
		cfg.ASNBurst = defaults.ASNBurst
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = defaults.CleanupInterval
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = defaults.MaxAge
	}
	// Backfill entry caps independently of the IPRate check above so a
	// caller-supplied Config that sets IPRate but not the caps still gets
	// bounded maps instead of silently growing unbounded.
	if cfg.MaxIPEntries == 0 {
		cfg.MaxIPEntries = defaultMaxIPLimiters
	}
	if cfg.MaxASNEntries == 0 {
		cfg.MaxASNEntries = defaultMaxASNLimiters
	}

	l := &Limiter{
		ipLimiters:      make(map[string]*TokenBucket),
		asnLimiters:     make(map[string]*TokenBucket),
		ipRate:          cfg.IPRate,
		asnRate:         cfg.ASNRate,
		ipBurst:         cfg.IPBurst,
		asnBurst:        cfg.ASNBurst,
		maxIPLimiters:   cfg.MaxIPEntries,
		maxASNLimiters:  cfg.MaxASNEntries,
		cleanupInterval: cfg.CleanupInterval,
		maxAge:          cfg.MaxAge,
		lastCleanup:     time.Now(),
	}

	// Start cleanup goroutine
	go l.cleanupLoop()

	return l
}

// evictOldestLocked removes the least-recently-used entry from m to keep a
// limiter map bounded when it is full. Caller must hold l.mu.
// SIMPLIFIED: linear scan for the oldest entry; fine at the default
// hundred-thousand-entry cap. Switch to an intrusive LRU list if profiling
// shows eviction cost matters at larger caps.
func evictOldestLocked(m map[string]*TokenBucket) {
	var oldestKey string
	var oldestSeen time.Time
	found := false

	for key, tb := range m {
		tb.mu.Lock()
		lastSeen := tb.lastSeen
		tb.mu.Unlock()

		if !found || lastSeen.Before(oldestSeen) {
			oldestKey = key
			oldestSeen = lastSeen
			found = true
		}
	}

	if found {
		delete(m, oldestKey)
	}
}

// AllowIP checks if a request from an IP is allowed
func (l *Limiter) AllowIP(ip net.IP) bool {
	if ip == nil {
		return true // Allow if no IP
	}

	ipStr := ip.String()

	// Fast path: the bucket almost always exists, and every collector
	// stream funnels through this limiter — take the read lock unless we
	// actually have to insert.
	l.mu.RLock()
	limiter, ok := l.ipLimiters[ipStr]
	l.mu.RUnlock()
	if !ok {
		l.mu.Lock()
		if limiter, ok = l.ipLimiters[ipStr]; !ok {
			if len(l.ipLimiters) >= l.maxIPLimiters {
				evictOldestLocked(l.ipLimiters)
			}
			limiter = NewTokenBucket(l.ipBurst, l.ipRate)
			l.ipLimiters[ipStr] = limiter
		}
		l.mu.Unlock()
	}

	return limiter.Allow()
}

// AllowASN checks if a request from an ASN is allowed
func (l *Limiter) AllowASN(asn string) bool {
	// "" means no ASN was resolved at all; UnknownASN means the GeoIP DB
	// looked it up and failed to resolve one. Neither identifies a real ASN,
	// so bucketing on either would let every unrelated unresolved-ASN client
	// share (and have drained for them) a single bucket. Fall back to
	// per-IP-only limiting for both.
	if asn == "" || asn == UnknownASN {
		return true
	}

	l.mu.RLock()
	limiter, ok := l.asnLimiters[asn]
	l.mu.RUnlock()
	if !ok {
		l.mu.Lock()
		if limiter, ok = l.asnLimiters[asn]; !ok {
			if len(l.asnLimiters) >= l.maxASNLimiters {
				evictOldestLocked(l.asnLimiters)
			}
			limiter = NewTokenBucket(l.asnBurst, l.asnRate)
			l.asnLimiters[asn] = limiter
		}
		l.mu.Unlock()
	}

	return limiter.Allow()
}

// Allow checks both IP and ASN rate limits
func (l *Limiter) Allow(ip net.IP, asn string) bool {
	ipAllowed := l.AllowIP(ip)
	asnAllowed := l.AllowASN(asn)
	return ipAllowed && asnAllowed
}

// SetIPRate updates the per-IP rate limit, including for every currently
// tracked IP, so a runtime rate change takes effect immediately instead of
// only applying to IPs first seen after the call.
func (l *Limiter) SetIPRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ipRate = rate
	for _, limiter := range l.ipLimiters {
		limiter.setRate(rate, l.ipBurst)
	}
}

// SetASNRate updates the per-ASN rate limit, including for every currently
// tracked ASN, so a runtime rate change takes effect immediately instead of
// only applying to ASNs first seen after the call.
func (l *Limiter) SetASNRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asnRate = rate
	for _, limiter := range l.asnLimiters {
		limiter.setRate(rate, l.asnBurst)
	}
}

// GetStats returns current limiter statistics
func (l *Limiter) GetStats() (ipCount, asnCount int) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.ipLimiters), len(l.asnLimiters)
}

// cleanupLoop periodically removes old limiters to prevent memory leaks
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		l.cleanup()
	}
}

// cleanup removes limiters that haven't been used recently
func (l *Limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.maxAge)

	// Clean IP limiters
	for ip, limiter := range l.ipLimiters {
		limiter.mu.Lock()
		lastSeen := limiter.lastSeen
		limiter.mu.Unlock()

		if lastSeen.Before(cutoff) {
			delete(l.ipLimiters, ip)
		}
	}

	// Clean ASN limiters
	for asn, limiter := range l.asnLimiters {
		limiter.mu.Lock()
		lastSeen := limiter.lastSeen
		limiter.mu.Unlock()

		if lastSeen.Before(cutoff) {
			delete(l.asnLimiters, asn)
		}
	}

	l.lastCleanup = now
}
