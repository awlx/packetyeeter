package botverify

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	metrics "PacketYeeter/pkg/metrics"
)

// BotType represents the type of verified bot
type BotType string

const (
	BotTypeGooglebot   BotType = "googlebot"
	BotTypeBingbot     BotType = "bingbot"
	BotTypeBaiduspider BotType = "baiduspider"
	BotTypeYandexBot   BotType = "yandexbot"
	BotTypeFacebookBot BotType = "facebookbot"
	BotTypeTwitterBot  BotType = "twitterbot"
	BotTypeSlackBot    BotType = "slackbot"
	BotTypeUnknown     BotType = "unknown"
)

// BotPattern holds user-agent patterns and verification rules for known bots
type BotPattern struct {
	Type           BotType
	UserAgentMatch string   // Substring to match in User-Agent
	ReverseDNS     []string // Valid reverse DNS suffixes
	OrgPatterns    []string // Valid organization name patterns from GeoIP (fallback)
	RequireForward bool     // Require forward DNS verification
}

// KnownBots contains patterns for verified legitimate bots
var KnownBots = []BotPattern{
	{
		Type:           BotTypeGooglebot,
		UserAgentMatch: "Googlebot",
		ReverseDNS:     []string{".googlebot.com", ".google.com"},
		RequireForward: true,
	},
	{
		Type:           BotTypeBingbot,
		UserAgentMatch: "bingbot",
		ReverseDNS:     []string{".search.msn.com"},
		RequireForward: true,
	},
	{
		Type:           BotTypeBaiduspider,
		UserAgentMatch: "Baiduspider",
		ReverseDNS:     []string{".crawl.baidu.com", ".crawl.baidu.jp"},
		RequireForward: true,
	},
	{
		Type:           BotTypeYandexBot,
		UserAgentMatch: "YandexBot",
		ReverseDNS:     []string{".yandex.com", ".yandex.net", ".yandex.ru"},
		RequireForward: true,
	},
	{
		Type:           BotTypeFacebookBot,
		UserAgentMatch: "facebookexternalhit",
		ReverseDNS:     []string{".facebook.com", ".fbsv.net"},
		OrgPatterns:    []string{"Facebook", "Meta"},
		RequireForward: true,
	},
	{
		Type:           BotTypeTwitterBot,
		UserAgentMatch: "Twitterbot",
		ReverseDNS:     []string{".twitter.com"},
		OrgPatterns:    []string{"Twitter"},
		RequireForward: true,
	},
	{
		Type:           BotTypeSlackBot,
		UserAgentMatch: "Slackbot",
		ReverseDNS:     []string{".slack.com"},
		RequireForward: true,
	},
}

// VerificationResult represents the result of bot verification
type VerificationResult struct {
	IsVerified bool
	BotType    BotType
	ReverseDNS string
	ForwardDNS []string
	VerifiedAt time.Time
	// TransientFailure marks a verification that could not complete (DNS
	// timeout, SERVFAIL, network error). It is not evidence of impersonation:
	// a transient hiccup on a real crawler's PTR must not read as a spoofed
	// bot. Cached only for transientFailTTL so verification retries soon.
	TransientFailure bool
	// ConsecutiveTransientFailures counts back-to-back re-verification cycles
	// that ended in a transient failure for this IP, with no definitive
	// result in between. The "transient" classification is attacker
	// influenceable: whoever controls an IP block controls its PTR zone and
	// can serve SERVFAIL/timeouts indefinitely, so unbounded forgiveness of
	// transient failures would be a permanent impersonation free pass. Any
	// definitive result (verified, NXDOMAIN, DNS mismatch) resets this to 0.
	ConsecutiveTransientFailures int
	ErrorMessage                 string
	// Pending: no cached verdict yet and a lookup is queued or running.
	// Carries neither verification nor impersonation.
	Pending bool
	// Dropped: no cached verdict and none due in time: no lookup was started
	// (queue or cache full, or verifier closed), or it has been pending
	// longer than dnsTimeout. Carries neither verification nor impersonation.
	Dropped bool
}

// IsForgivenTransientFailure reports whether this result is a transient DNS
// failure that is still within the forgiveness cap and therefore must NOT be
// treated as impersonation. It centralizes the rule so every consumer (the
// HTTP handler and the gRPC VerifyBot RPC) agrees: a real crawler with a
// briefly-flaky PTR is not a spoofer, but the forgiveness is bounded so an
// attacker serving SERVFAIL forever eventually falls through to impersonation.
func (r *VerificationResult) IsForgivenTransientFailure() bool {
	return r != nil && r.TransientFailure &&
		r.ConsecutiveTransientFailures <= maxConsecutiveTransientFailures
}

// transientFailTTL bounds how long a could-not-complete verification is
// served from cache before re-verifying. The regular cacheTTL (default 1h)
// would turn one DNS hiccup into an hour of unverified treatment for a
// legitimate crawler.
const transientFailTTL = 1 * time.Minute

// maxConsecutiveTransientFailures caps how many consecutive transient-DNS
// re-verification cycles an IP gets the forgiving no-penalty treatment.
// Past the cap the failure is handled exactly like a definitive one
// (impersonation + penalty). Cycles are transientFailTTL (1m) apart, so 5
// tolerates ~5 minutes of genuine resolver/PTR outage — enough for typical
// transient DNS incidents — while bounding an attacker-controlled PTR zone
// (deliberate SERVFAIL/timeout) to a ~5 minute unpenalized window per IP,
// independent of request rate. During that window the client is merely
// unverified, never verified.
const maxConsecutiveTransientFailures = 5

// isTransientDNSError reports whether a lookup error is a transient resolver
// problem rather than a definitive answer. NXDOMAIN ("no such host") is
// definitive - the IP genuinely has no PTR / the name has no records - while
// timeouts, SERVFAIL, and network errors say nothing about the peer.
func isTransientDNSError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsNotFound
	}
	return true
}

// GeoIPProvider interface for GeoIP lookups
type GeoIPProvider interface {
	Lookup(ip net.IP) (asn string, org string)
}

// Verifier handles bot verification with caching
type Verifier struct {
	mu              sync.RWMutex
	cache           map[string]*VerificationResult // IP -> result
	cacheTTL        time.Duration
	patterns        []BotPattern
	dnsTimeout      time.Duration
	verifyInFlight  map[string]*sync.Mutex // Prevent duplicate verifications
	geoIP           GeoIPProvider          // GeoIP for ASN/org-based fallback verification
	maxCacheEntries int
	resolver        *net.Resolver // injectable for tests; DNS calls honor dnsTimeout

	// DNS lookup seams, injectable for deterministic tests. They take the
	// caller's context so verifyDNS can bound the whole verification (reverse +
	// forward) under a single shared deadline rather than giving each lookup its
	// own, which would let a hostile PTR zone multiply the total stall.
	lookupAddr func(ctx context.Context, addr string) ([]string, error)
	lookupHost func(ctx context.Context, host string) ([]string, error)

	// Async lookup pool for VerifyAsync. queued holds IPs that are queued or
	// being looked up, with their enqueue time (guarded by mu), so a burst
	// from one IP costs one lookup.
	queue  chan asyncJob
	queued map[string]time.Time
	ctx    context.Context // cancelled by Close; parent of every DNS lookup
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type asyncJob struct {
	ip      net.IP
	pattern *BotPattern
}

// Pool sizing: a lookup that never answers holds a worker for dnsTimeout, so
// throughput under a tarpitting PTR zone is roughly workers/dnsTimeout; the
// queue absorbs bursts and anything beyond it is dropped, never waited on.
const (
	defaultAsyncWorkers   = 16
	defaultAsyncQueueSize = 1024
)

// NewVerifier creates a new bot verifier
func NewVerifier(cacheTTL, dnsTimeout time.Duration) *Verifier {
	return NewVerifierWithGeoIP(cacheTTL, dnsTimeout, nil)
}

// NewVerifierWithGeoIP creates a new bot verifier with GeoIP support
func NewVerifierWithGeoIP(cacheTTL, dnsTimeout time.Duration, geoIP GeoIPProvider) *Verifier {
	return newVerifier(cacheTTL, dnsTimeout, geoIP, defaultAsyncWorkers, defaultAsyncQueueSize)
}

func newVerifier(cacheTTL, dnsTimeout time.Duration, geoIP GeoIPProvider, workers, queueSize int) *Verifier {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Hour
	}
	if dnsTimeout == 0 {
		dnsTimeout = 2 * time.Second
	}

	v := &Verifier{
		cache:           make(map[string]*VerificationResult),
		cacheTTL:        cacheTTL,
		patterns:        KnownBots,
		dnsTimeout:      dnsTimeout,
		verifyInFlight:  make(map[string]*sync.Mutex),
		geoIP:           geoIP,
		maxCacheEntries: 50000,
		resolver:        net.DefaultResolver,
		queue:           make(chan asyncJob, queueSize),
		queued:          make(map[string]time.Time),
	}
	v.ctx, v.cancel = context.WithCancel(context.Background())
	// Default DNS seams call the resolver with the caller-supplied context.
	// They read v.resolver at call time so a test overriding it (or the whole
	// seam) takes effect. verifyDNS supplies a single dnsTimeout-bounded context
	// covering the whole verification, so a hostile PTR zone cannot hold a
	// worker (or a synchronous Verify caller) beyond one dnsTimeout.
	v.lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		return v.resolver.LookupAddr(ctx, addr)
	}
	v.lookupHost = func(ctx context.Context, host string) ([]string, error) {
		return v.resolver.LookupHost(ctx, host)
	}

	v.wg.Add(1 + workers)
	go v.cleanupLoop()
	for range workers {
		go v.worker()
	}

	return v
}

// SetResolver replaces the DNS resolver (e.g. a local caching resolver). Call
// it before the first verification.
func (v *Verifier) SetResolver(r *net.Resolver) {
	v.resolver = r
}

// Close stops the lookup workers and cleanup loop, cancelling in-flight DNS
// lookups, and waits for them to exit. Queued lookups are discarded.
func (v *Verifier) Close() {
	v.cancel()
	v.wg.Wait()
	v.mu.Lock()
	clear(v.queued) // discarded jobs must not read as pending forever
	v.mu.Unlock()
}

// VerifyAsync is Verify for the signal-stream hot path: it never waits on DNS.
// On a cache miss for a known-bot User-Agent it queues a lookup and returns a
// Pending result (or Dropped if the queue is full); the lookup's verdict is
// cached for later requests from the IP.
func (v *Verifier) VerifyAsync(ip net.IP, userAgent string) *VerificationResult {
	if ip == nil || userAgent == "" {
		return &VerificationResult{IsVerified: false, ErrorMessage: "missing IP or User-Agent"}
	}
	ipStr := ip.String()
	if cached := v.cachedResult(ipStr); cached != nil {
		return cached
	}
	pattern := v.matchPattern(userAgent)
	if pattern == nil {
		return &VerificationResult{IsVerified: false, BotType: BotTypeUnknown}
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	// Re-check under the lock: a worker stores the verdict and clears queued
	// in one critical section, so we see one or the other.
	if cached, ok := v.cache[ipStr]; ok && time.Since(cached.VerifiedAt) < v.cachedResultTTL(cached) {
		return cached
	}
	if since, inFlight := v.queued[ipStr]; inFlight {
		// Pending skips heuristics, so cap it at what an inline lookup would
		// have cost; otherwise a backlog (e.g. a flood of tarpitting PTR
		// zones) stretches the bypass to minutes per IP.
		if time.Since(since) > v.dnsTimeout {
			return &VerificationResult{BotType: pattern.Type, Dropped: true, ErrorMessage: "verification backlog"}
		}
		return &VerificationResult{BotType: pattern.Type, Pending: true}
	}
	if v.ctx.Err() != nil {
		return &VerificationResult{BotType: pattern.Type, Dropped: true, ErrorMessage: "verifier closed"}
	}
	_, hasEntry := v.cache[ipStr]
	if !hasEntry && len(v.cache) >= v.maxCacheEntries {
		// The verdict could not be cached, so Pending would never resolve and
		// would become a permanent heuristics bypass for every new IP.
		metrics.BotVerificationQueueDrops.WithLabelValues("cache_full").Inc()
		return &VerificationResult{BotType: pattern.Type, Dropped: true, ErrorMessage: "verification cache full"}
	}
	select {
	case v.queue <- asyncJob{ip: ip, pattern: pattern}:
		v.queued[ipStr] = time.Now()
		metrics.BotVerificationQueueDepth.Set(float64(len(v.queue)))
		return &VerificationResult{BotType: pattern.Type, Pending: true}
	default:
		metrics.BotVerificationQueueDrops.WithLabelValues("queue_full").Inc()
		return &VerificationResult{BotType: pattern.Type, Dropped: true, ErrorMessage: "verification queue full"}
	}
}

func (v *Verifier) worker() {
	defer v.wg.Done()
	for {
		select {
		case <-v.ctx.Done():
			return
		case job := <-v.queue:
			metrics.BotVerificationQueueDepth.Set(float64(len(v.queue)))
			ipStr := job.ip.String()
			result := v.verifyDNS(job.ip, job.pattern)
			v.mu.Lock()
			// A lookup cut short by shutdown says nothing about the peer.
			if v.ctx.Err() == nil {
				v.storeLocked(ipStr, result)
			}
			delete(v.queued, ipStr)
			v.mu.Unlock()
		}
	}
}

func (v *Verifier) cachedResult(ipStr string) *VerificationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if cached, ok := v.cache[ipStr]; ok && time.Since(cached.VerifiedAt) < v.cachedResultTTL(cached) {
		return cached
	}
	return nil
}

func (v *Verifier) matchPattern(userAgent string) *BotPattern {
	for i := range v.patterns {
		if strings.Contains(userAgent, v.patterns[i].UserAgentMatch) {
			return &v.patterns[i]
		}
	}
	return nil
}

// Verify checks if the given IP and User-Agent represent a verified bot
func (v *Verifier) Verify(ip net.IP, userAgent string) *VerificationResult {
	if ip == nil || userAgent == "" {
		return &VerificationResult{IsVerified: false, ErrorMessage: "missing IP or User-Agent"}
	}

	ipStr := ip.String()

	if cached := v.cachedResult(ipStr); cached != nil {
		return cached
	}

	pattern := v.matchPattern(userAgent)
	if pattern == nil {
		// Not a known bot pattern
		return &VerificationResult{IsVerified: false, BotType: BotTypeUnknown}
	}

	// Prevent duplicate in-flight verifications
	v.mu.Lock()
	mu, exists := v.verifyInFlight[ipStr]
	if !exists {
		mu = &sync.Mutex{}
		v.verifyInFlight[ipStr] = mu
	}
	v.mu.Unlock()

	// Lock for this IP's verification
	mu.Lock()
	defer func() {
		mu.Unlock()
		v.mu.Lock()
		if v.verifyInFlight[ipStr] == mu {
			delete(v.verifyInFlight, ipStr)
		}
		v.mu.Unlock()
	}()

	// Double-check cache after acquiring lock
	if cached := v.cachedResult(ipStr); cached != nil {
		return cached
	}

	result := v.verifyDNS(ip, pattern)

	v.mu.Lock()
	v.storeLocked(ipStr, result)
	v.mu.Unlock()

	return result
}

// storeLocked caches result, accumulating the consecutive-transient counter
// under the caller's v.mu lock so concurrent verifications cannot lose counts.
func (v *Verifier) storeLocked(ipStr string, result *VerificationResult) {
	prev, exists := v.cache[ipStr]
	if result.TransientFailure {
		if exists && prev.TransientFailure {
			// The previous entry survives in the cache for the full cacheTTL
			// even though it is only *served* for transientFailTTL, so the
			// counter persists across re-verification cycles: an attacker
			// cannot reset it by simply triggering another transient lookup.
			// It only resets via a definitive result below (overwrite with
			// TransientFailure=false) or after the IP goes idle past
			// cacheTTL — accepted residual: an hour of silence buys at most
			// maxConsecutiveTransientFailures fresh forgiven cycles.
			result.ConsecutiveTransientFailures = prev.ConsecutiveTransientFailures + 1
		} else {
			result.ConsecutiveTransientFailures = 1
		}
	}
	if exists || len(v.cache) < v.maxCacheEntries {
		v.cache[ipStr] = result
	} else if result.TransientFailure {
		// Fail closed: the cache is saturated and this IP's counter cannot be
		// tracked. Handing out an untracked forgiving pass here would let an
		// attacker reset the cap at will by keeping the cache full (50k
		// bot-claiming IPs — itself an attack condition), so treat the
		// failure as over-cap instead. Definitive results are unaffected.
		result.ConsecutiveTransientFailures = maxConsecutiveTransientFailures + 1
	}
}

// verifyDNS performs reverse and forward DNS verification
func (v *Verifier) verifyDNS(ip net.IP, pattern *BotPattern) *VerificationResult {
	result := &VerificationResult{
		BotType:    pattern.Type,
		VerifiedAt: time.Now(),
	}

	// A single overall deadline bounds the whole verification (reverse PTR plus
	// any forward-confirm lookup). Giving each lookup its own dnsTimeout let the
	// total blow out to N*dnsTimeout and let a hostile PTR zone multiply the
	// stall by chaining lookups; one shared deadline caps the total budget.
	ctx, cancel := context.WithTimeout(v.ctx, v.dnsTimeout)
	defer cancel()

	// Reverse DNS lookup (shares the verification-wide deadline).
	names, err := v.lookupAddr(ctx, ip.String())
	if err != nil {
		logrus.WithError(err).Debug("Reverse DNS lookup failed")
		result.TransientFailure = isTransientDNSError(err)
		result.ErrorMessage = "reverse DNS failed"
		return result
	}

	if len(names) == 0 {
		result.ErrorMessage = "no reverse DNS"
		return result
	}

	reverseDNS := strings.TrimSuffix(names[0], ".")
	result.ReverseDNS = reverseDNS

	// Check if reverse DNS matches expected suffixes
	valid := false
	for _, suffix := range pattern.ReverseDNS {
		if strings.HasSuffix(reverseDNS, suffix) {
			valid = true
			break
		}
	}

	if !valid {
		// DNS failed, try GeoIP org-based verification as fallback
		if v.geoIP != nil && len(pattern.OrgPatterns) > 0 {
			_, org := v.geoIP.Lookup(ip)
			for _, orgPattern := range pattern.OrgPatterns {
				if strings.Contains(org, orgPattern) {
					logrus.WithFields(logrus.Fields{
						"ip":       ip.String(),
						"org":      org,
						"bot_type": pattern.Type,
					}).Debug("Bot verified via GeoIP organization")
					result.IsVerified = true
					result.ReverseDNS = "verified-via-geoip-org: " + org
					return result
				}
			}
		}
		result.ErrorMessage = "reverse DNS mismatch"
		return result
	}

	// Forward DNS verification (if required)
	if pattern.RequireForward {
		addrs, err := v.lookupHost(ctx, reverseDNS)
		if err != nil {
			logrus.WithError(err).Debug("Forward DNS lookup failed")
			result.TransientFailure = isTransientDNSError(err)
			result.ErrorMessage = "forward DNS failed"
			return result
		}

		result.ForwardDNS = addrs

		// Check if original IP is in forward DNS results
		ipStr := ip.String()
		found := false
		for _, addr := range addrs {
			if addr == ipStr {
				found = true
				break
			}
		}

		if !found {
			result.ErrorMessage = "forward DNS mismatch"
			return result
		}
	}

	// Verification passed
	result.IsVerified = true

	logrus.WithFields(logrus.Fields{
		"ip":          ip.String(),
		"bot_type":    pattern.Type,
		"reverse_dns": reverseDNS,
	}).Info("Bot verified")

	return result
}

// IsKnownBot checks if a User-Agent matches any known bot pattern
func IsKnownBot(userAgent string) bool {
	for _, pattern := range KnownBots {
		if strings.Contains(userAgent, pattern.UserAgentMatch) {
			return true
		}
	}
	return false
}

// GetBotType returns the bot type based on User-Agent
func GetBotType(userAgent string) BotType {
	for _, pattern := range KnownBots {
		if strings.Contains(userAgent, pattern.UserAgentMatch) {
			return pattern.Type
		}
	}
	return BotTypeUnknown
}

// cachedResultTTL returns how long a cached result stays valid: completed
// verifications (verified or definitively failed) use the full cacheTTL,
// transient failures only transientFailTTL.
func (v *Verifier) cachedResultTTL(result *VerificationResult) time.Duration {
	if result.TransientFailure {
		return transientFailTTL
	}
	return v.cacheTTL
}

// cleanupLoop periodically removes expired cache entries
func (v *Verifier) cleanupLoop() {
	defer v.wg.Done()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			v.cleanup()
		}
	}
}

// cleanup removes expired cache entries
func (v *Verifier) cleanup() {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	for ip, result := range v.cache {
		if now.Sub(result.VerifiedAt) > v.cacheTTL {
			delete(v.cache, ip)
		}
	}
}

// GetCacheStats returns cache statistics
func (v *Verifier) GetCacheStats() (size int, verified int) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	size = len(v.cache)
	for _, result := range v.cache {
		if result.IsVerified {
			verified++
		}
	}
	return
}
