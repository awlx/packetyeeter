package ratelimit

import (
	"net"
	"sync"
	"time"
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

// Limiter manages rate limiting for IPs and ASNs
type Limiter struct {
	mu sync.RWMutex

	ipLimiters  map[string]*TokenBucket
	asnLimiters map[string]*TokenBucket

	ipRate  float64 // Requests per second per IP
	asnRate float64 // Requests per second per ASN

	ipBurst  float64 // Burst capacity per IP
	asnBurst float64 // Burst capacity per ASN

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

	l := &Limiter{
		ipLimiters:      make(map[string]*TokenBucket),
		asnLimiters:     make(map[string]*TokenBucket),
		ipRate:          cfg.IPRate,
		asnRate:         cfg.ASNRate,
		ipBurst:         cfg.IPBurst,
		asnBurst:        cfg.ASNBurst,
		cleanupInterval: cfg.CleanupInterval,
		maxAge:          cfg.MaxAge,
		lastCleanup:     time.Now(),
	}

	// Start cleanup goroutine
	go l.cleanupLoop()

	return l
}

// AllowIP checks if a request from an IP is allowed
func (l *Limiter) AllowIP(ip net.IP) bool {
	if ip == nil {
		return true // Allow if no IP
	}

	ipStr := ip.String()

	l.mu.Lock()
	limiter, ok := l.ipLimiters[ipStr]
	if !ok {
		limiter = NewTokenBucket(l.ipBurst, l.ipRate)
		l.ipLimiters[ipStr] = limiter
	}
	l.mu.Unlock()

	return limiter.Allow()
}

// AllowASN checks if a request from an ASN is allowed
func (l *Limiter) AllowASN(asn string) bool {
	if asn == "" {
		return true // Allow if no ASN
	}

	l.mu.Lock()
	limiter, ok := l.asnLimiters[asn]
	if !ok {
		limiter = NewTokenBucket(l.asnBurst, l.asnRate)
		l.asnLimiters[asn] = limiter
	}
	l.mu.Unlock()

	return limiter.Allow()
}

// Allow checks both IP and ASN rate limits
func (l *Limiter) Allow(ip net.IP, asn string) bool {
	ipAllowed := l.AllowIP(ip)
	asnAllowed := l.AllowASN(asn)
	return ipAllowed && asnAllowed
}

// SetIPRate updates the per-IP rate limit
func (l *Limiter) SetIPRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ipRate = rate
}

// SetASNRate updates the per-ASN rate limit
func (l *Limiter) SetASNRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asnRate = rate
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
