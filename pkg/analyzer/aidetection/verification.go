package aidetection

import (
	"PacketYeeter/pkg/analyzer/ja4db"
	"PacketYeeter/pkg/metrics"
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// JA4Verifier interface for JA4 database lookups
type JA4Verifier interface {
	IsKnownBot(fingerprint string) bool
	GetInfo(fingerprint string) string
	Lookup(fingerprint string) (interface{}, bool)
	LookupWithType(fingerprint string, fpType string) (interface{}, bool)
}

// maxVerificationCacheEntries bounds the crawler verification cache so an
// attacker cannot exhaust memory by generating a large number of unique
// (IP, claimed-bot-name) pairs before their entries have a chance to expire
// via TTL. 20,000 entries comfortably covers verification traffic for a busy
// site's active crawler population while keeping worst-case memory usage
// (a few hundred bytes per entry) in the low megabytes.
const maxVerificationCacheEntries = 20000

// negativeVerificationCacheTTL is the TTL applied to failed/negative DNS
// verification results (NXDOMAIN, timeout, hostname/forward-DNS mismatch).
// It is intentionally much shorter than the TTL used for confirmed-good
// verifications so that a transient DNS failure (or an attacker deliberately
// poisoning the cache for a victim IP right before a legitimate crawler
// visits) self-heals quickly instead of denying that IP verified status for
// the full positive-result TTL.
const negativeVerificationCacheTTL = 30 * time.Second

// CrawlerVerifier verifies bot identity claims via DNS/PTR lookups
type CrawlerVerifier struct {
	// Known crawler domains for verification
	verifiedDomains map[string][]string
	// JA4 database for fingerprint-based verification
	ja4DB JA4Verifier

	resolver         crawlerDNSResolver
	lookupTimeout    time.Duration
	cacheTTL         time.Duration
	negativeCacheTTL time.Duration
	maxCacheEntries  int
	// now allows tests to inject a fake clock; defaults to time.Now.
	now     func() time.Time
	cacheMu sync.Mutex
	cache   map[string]crawlerVerificationCacheEntry
}

// NewCrawlerVerifier creates a new crawler verifier
func NewCrawlerVerifier(ja4DB JA4Verifier) *CrawlerVerifier {
	return newCrawlerVerifier(ja4DB, defaultCrawlerResolver{}, 500*time.Millisecond, 10*time.Minute)
}

func newCrawlerVerifier(ja4DB JA4Verifier, resolver crawlerDNSResolver, timeout, cacheTTL time.Duration) *CrawlerVerifier {
	if resolver == nil {
		resolver = defaultCrawlerResolver{}
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if cacheTTL <= 0 {
		cacheTTL = 10 * time.Minute
	}
	negativeTTL := negativeVerificationCacheTTL
	if cacheTTL < negativeTTL {
		// Never let the negative TTL exceed the configured positive TTL
		// (relevant for tests/configs that use a very short cacheTTL).
		negativeTTL = cacheTTL
	}
	return &CrawlerVerifier{
		ja4DB:            ja4DB,
		resolver:         resolver,
		lookupTimeout:    timeout,
		cacheTTL:         cacheTTL,
		negativeCacheTTL: negativeTTL,
		maxCacheEntries:  maxVerificationCacheEntries,
		now:              time.Now,
		cache:            make(map[string]crawlerVerificationCacheEntry),
		verifiedDomains: map[string][]string{
			// Search engines
			"googlebot":   {".googlebot.com", ".google.com"},
			"bingbot":     {".search.msn.com"},
			"slurp":       {".crawl.yahoo.net"},
			"duckduckbot": {".duckduckgo.com"},
			"baiduspider": {".crawl.baidu.com", ".crawl.baidu.jp"},
			"yandexbot":   {".yandex.com", ".yandex.net", ".yandex.ru"},

			// AI crawlers
			"gptbot":             {".openai.com"},
			"claudebot":          {".anthropic.com"},
			"cohere-ai":          {".cohere.com"},
			"perplexitybot":      {".perplexity.ai"},
			"anthropic-ai":       {".anthropic.com"},
			"meta-externalagent": {".fbsv.net", ".facebook.com"},
			"bytespider":         {".bytedance.com"},

			// Social media
			"facebookexternalhit": {".fbsv.net", ".facebook.com"},
			"twitterbot":          {".twitter.com"},
			"linkedinbot":         {".linkedin.com"},

			// Monitoring
			"pingdom":     {".pingdom.com"},
			"uptimerobot": {".uptimerobot.com"},

			// SEO/marketing crawlers - widely used, well-documented,
			// respect robots.txt, and publish reverse-DNS verification
			// like the search engines above. Live production data showed
			// SEMrushBot traffic being blocked purely because it wasn't in
			// this list at all (VerificationSkipped, no dampening),
			// combined with the always-true bot_ua/missing_accept_language
			// signals every crawler naturally trips.
			"semrushbot": {".semrush.com"},
		},
	}
}

type crawlerDNSResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type defaultCrawlerResolver struct{}

func (defaultCrawlerResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

func (defaultCrawlerResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

type crawlerVerificationCacheEntry struct {
	status    VerificationStatus
	expiresAt time.Time
}

// VerifyCrawler attempts to verify a crawler's identity using reverse DNS
func (v *CrawlerVerifier) VerifyCrawler(ip net.IP, userAgent string) VerificationStatus {
	ua := strings.ToLower(userAgent)

	// Find potential crawler claim in user agent
	var claimedBot string
	for botName := range v.verifiedDomains {
		if strings.Contains(ua, botName) {
			claimedBot = botName
			break
		}
	}

	if claimedBot == "" {
		// No crawler claim found
		return VerificationSkipped
	}

	cacheKey := ip.String() + "|" + claimedBot
	if status, ok := v.cachedVerification(cacheKey); ok {
		return status
	}

	status := v.verifyCrawlerUncached(ip, claimedBot)
	v.storeVerification(cacheKey, status)
	return status
}

func (v *CrawlerVerifier) verifyCrawlerUncached(ip net.IP, claimedBot string) VerificationStatus {
	ctx, cancel := context.WithTimeout(context.Background(), v.lookupTimeout)
	defer cancel()

	// Perform reverse DNS lookup
	names, err := v.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		// A DNS lookup error (including NXDOMAIN, i.e. no PTR record at all)
		// is not evidence of anything - it just means we couldn't check.
		// Many legitimate crawler operators (e.g. Meta's meta-externalagent)
		// don't consistently publish PTR records for their crawler ranges,
		// so treating "no PTR" the same as "actively contradicts the claim"
		// (VerificationFailed) produced real false positives in production:
		// a genuine Meta crawler IP (confirmed via WHOIS) got scored as
		// verification-failed purely because it had no PTR record, which
		// fed a confidence bump that pushed it over the block threshold.
		// Report VerificationUnknown here instead so "couldn't determine"
		// doesn't get penalized the same as "confirmed not who it claims
		// to be".
		logrus.WithFields(logrus.Fields{
			"ip":    ip.String(),
			"error": err,
		}).Debug("Failed reverse DNS lookup")
		return VerificationUnknown
	}

	if len(names) == 0 {
		return VerificationUnknown
	}

	// Check if any reverse DNS name matches verified domains
	hostname := strings.TrimSuffix(strings.ToLower(names[0]), ".")
	expectedDomains := v.verifiedDomains[claimedBot]

	for _, domain := range expectedDomains {
		domain = strings.TrimSuffix(strings.ToLower(domain), ".")
		if strings.HasSuffix(hostname, domain) {
			// Verify forward DNS matches
			if v.verifyForwardDNS(ctx, hostname, ip) {
				return VerificationVerified
			}
		}
	}

	// A PTR record exists but resolves to a hostname that doesn't match any
	// expected domain for the claimed crawler - this is a real signal
	// (someone spoofing a well-known crawler's user agent from unrelated
	// infrastructure), unlike the "no PTR at all" case above.
	return VerificationFailed
}

// verifyForwardDNS checks that the hostname resolves back to the IP
func (v *CrawlerVerifier) verifyForwardDNS(ctx context.Context, hostname string, expectedIP net.IP) bool {
	ips, err := v.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.IP.Equal(expectedIP) {
			return true
		}
	}

	return false
}

func (v *CrawlerVerifier) cachedVerification(cacheKey string) (VerificationStatus, bool) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()

	entry, ok := v.cache[cacheKey]
	if !ok {
		return "", false
	}
	if v.now().After(entry.expiresAt) {
		delete(v.cache, cacheKey)
		return "", false
	}
	return entry.status, true
}

func (v *CrawlerVerifier) storeVerification(cacheKey string, status VerificationStatus) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()

	ttl := v.cacheTTL
	if status == VerificationFailed || status == VerificationUnknown {
		// Negative/indeterminate results get a much shorter TTL so
		// transient DNS failures, missing PTR records that get configured
		// later, or an attacker deliberately poisoning a victim IP's entry
		// don't deny verified status to a legitimate crawler for the full
		// TTL.
		ttl = v.negativeCacheTTL
	}

	if _, exists := v.cache[cacheKey]; !exists && len(v.cache) >= v.effectiveMaxCacheEntries() {
		v.evictOneLocked()
	}

	v.cache[cacheKey] = crawlerVerificationCacheEntry{
		status:    status,
		expiresAt: v.now().Add(ttl),
	}
}

func (v *CrawlerVerifier) effectiveMaxCacheEntries() int {
	if v.maxCacheEntries <= 0 {
		return maxVerificationCacheEntries
	}
	return v.maxCacheEntries
}

// evictOneLocked removes a single entry from the cache to make room for a
// new one once the size cap has been reached. It must be called with
// cacheMu held. It evicts the entry closest to expiry (oldest-first by
// remaining TTL) rather than an arbitrary/newest entry, so eviction doesn't
// cause cache-miss thrashing for entries that were just verified.
func (v *CrawlerVerifier) evictOneLocked() {
	var oldestKey string
	var oldestExpiry time.Time
	first := true
	for key, entry := range v.cache {
		if first || entry.expiresAt.Before(oldestExpiry) {
			oldestKey = key
			oldestExpiry = entry.expiresAt
			first = false
		}
	}
	if !first {
		delete(v.cache, oldestKey)
	}
}

func formatJA4Info(entry ja4db.JA4Entry) string {
	info := entry.Application
	if entry.Library != "" {
		info += " (" + entry.Library + ")"
	}
	if entry.Device != "" {
		info += " on " + entry.Device
	}
	if entry.Verified {
		info += " [verified]"
	}
	return info
}

var knownBotKeywords = []string{
	"gptbot", "claudebot", "cohere", "perplexity", "anthropic",
	"googlebot", "bingbot", "slurp", "duckduck", "baiduspider", "yandexbot",
	"facebookexternalhit", "twitterbot", "linkedinbot", "bytespider", "meta-externalagent",
	"pingdom", "uptimerobot",
}

func detectClaimedBot(userAgent string) string {
	ua := strings.ToLower(userAgent)
	for _, botName := range knownBotKeywords {
		if strings.Contains(ua, botName) {
			return botName
		}
	}
	return ""
}

func detectEntryBot(entry ja4db.JA4Entry) string {
	lower := entry.GetSearchableText()
	for _, botName := range knownBotKeywords {
		if strings.Contains(lower, botName) {
			return botName
		}
	}
	return ""
}

var browserKeywords = []string{
	"chrome", "chromium", "firefox", "safari", "edge", "edg/", "opr/", "opera", "brave", "vivaldi",
	"crios", "fxios", "android", "ios", "iphone", "ipad",
}

func IsBrowserInfo(infoLower string) bool {
	for _, kw := range browserKeywords {
		if strings.Contains(infoLower, kw) {
			// avoid headless matches
			if strings.Contains(infoLower, "headless") {
				continue
			}
			return true
		}
	}
	return false
}

func IsBrowserUA(uaLower string) bool {
	return ja4db.IsBrowserInfo(uaLower)
}

// CategorizeBot determines the bot category based on signals and user agent
func (v *CrawlerVerifier) CategorizeBot(userAgent, ja4, ja4h, ja4t, ja4Info string, signalTypes map[SignalType]int, sources map[SignalSource]int, verified VerificationStatus) BotCategory {
	// First check if we have JA4 info passed from the signal (avoids duplicate lookup)
	info := ja4Info
	var entry ja4db.JA4Entry
	var matchedType string
	lookupAttempted := false
	found := false

	// If not provided, look it up in the database with type hints
	if info == "" && v.ja4DB != nil {
		attempt := func(fp, fpType string) bool {
			if fp == "" {
				return false
			}
			lookupAttempted = true
			iface, ok := v.ja4DB.LookupWithType(fp, fpType)
			if !ok {
				return false
			}
			cast, ok := iface.(ja4db.JA4Entry)
			if !ok {
				return false
			}
			entry = cast
			matchedType = fpType
			return true
		}

		found = attempt(ja4, "ja4") || attempt(ja4h, "ja4h") || attempt(ja4t, "ja4t")
		if found {
			info = formatJA4Info(entry)
		} else if lookupAttempted {
			metrics.JA4DBMismatch.WithLabelValues("not_found").Inc()
		}
	}

	claimedBot := detectClaimedBot(userAgent)
	entryBot := ""
	if found {
		entryBot = detectEntryBot(entry)
		// Mismatches: UA claims bot but entry unverified or conflicts; or verified entry but UA silent
		if claimedBot != "" {
			if entryBot != "" && entryBot != claimedBot {
				metrics.JA4DBMismatch.WithLabelValues("ua_conflict").Inc()
			} else if !entry.Verified {
				metrics.JA4DBMismatch.WithLabelValues("ua_claim_unverified").Inc()
			}
		} else if entry.Verified && entryBot != "" {
			metrics.JA4DBMismatch.WithLabelValues("verified_no_claim").Inc()
		}
	}

	// Categorize based on JA4 database info if available
	if info != "" {
		logrus.WithFields(logrus.Fields{
			"ja4":        ja4,
			"ja4h":       ja4h,
			"ja4t":       ja4t,
			"match_type": matchedType,
			"ja4_info":   info,
		}).Info("JA4 database match found")

		// Categorize based on JA4 database info
		infoLower := strings.ToLower(info)
		if IsBrowserInfo(infoLower) {
			return BotCategoryBrowser
		}
		if strings.Contains(infoLower, "verified") {
			if strings.Contains(infoLower, "gptbot") || strings.Contains(infoLower, "claudebot") ||
				strings.Contains(infoLower, "cohere") || strings.Contains(infoLower, "perplexity") ||
				strings.Contains(infoLower, "anthropic") {
				return BotCategoryAICrawlerVerified
			}
			if strings.Contains(infoLower, "googlebot") || strings.Contains(infoLower, "bingbot") ||
				strings.Contains(infoLower, "slurp") || strings.Contains(infoLower, "duckduck") {
				return BotCategorySearchEngine
			}
			return BotCategoryLegitimate
		}
	}

	// UA fallback for browsers when no info
	if userAgent != "" && IsBrowserUA(strings.ToLower(userAgent)) {
		return BotCategoryBrowser
	}

	ua := strings.ToLower(userAgent)

	// Check for verified bots from DNS verification
	// Note: verified parameter removed as it should be determined via ja4DB or DNS
	// AI crawlers
	if strings.Contains(ua, "gptbot") || strings.Contains(ua, "claudebot") ||
		strings.Contains(ua, "cohere") || strings.Contains(ua, "perplexity") ||
		strings.Contains(ua, "anthropic") {
		return BotCategoryAICrawlerUnknown
	}

	// Search engines
	if strings.Contains(ua, "googlebot") || strings.Contains(ua, "bingbot") ||
		strings.Contains(ua, "slurp") || strings.Contains(ua, "duckduck") ||
		strings.Contains(ua, "yandex") || strings.Contains(ua, "baidu") {
		// Upgrade to verified search_engine if DNS verification passed
		if verified == VerificationVerified {
			return BotCategorySearchEngine
		}
		return BotCategorySearchUnknown
	}

	// Monitoring services
	if strings.Contains(ua, "pingdom") || strings.Contains(ua, "uptime") ||
		strings.Contains(ua, "monitor") {
		return BotCategoryMonitoring
	}

	// Check for script/scraper patterns
	uaPatterns := []struct {
		needle string
		cat    BotCategory
	}{
		{"crawlee", BotCategoryScraper},
		{"apify", BotCategoryScraper},
		{"apify_client", BotCategoryScraper},
		{"scrapy", BotCategoryScraper},
		{"playwright", BotCategoryScraper},
		{"puppeteer", BotCategoryScraper},
		{"headlesschrome", BotCategoryScraper},
		{"chrome-lighthouse", BotCategoryScraper},
		{"python-requests", BotCategoryScript},
		{"httpx", BotCategoryScript},
		{"aiohttp", BotCategoryScript},
		{"curl", BotCategoryScript},
		{"wget", BotCategoryScript},
		{"go-http", BotCategoryScript},
		{"okhttp", BotCategoryScript},
		{"httpclient", BotCategoryScript},
		{"axios", BotCategoryScript},
		{"node-fetch", BotCategoryScript},
		{"postman", BotCategoryScript},
		{"insomnia", BotCategoryScript},
		{"ruby", BotCategoryScript},
		{"java/", BotCategoryScript},
	}
	for _, p := range uaPatterns {
		if strings.Contains(ua, p.needle) {
			return p.cat
		}
	}

	// Signal-driven categorization
	if signalTypes[SignalPortScanning] > 0 {
		return BotCategoryScanner
	}
	floodSignals := signalTypes[SignalICMPFlood] + signalTypes[SignalUDPFlood] + signalTypes[SignalSYNFlood]
	if floodSignals >= 1 || signalTypes[SignalHighFrequency] > 0 || signalTypes[SignalIncompleteHandshake] > 50 {
		return BotCategoryDDoS
	}
	browserShapeAnomaly := signalTypes[SignalHeaderOrderAnomaly] > 0 ||
		signalTypes[SignalMissingSecCH] > 0 ||
		signalTypes[SignalMissingSecFetch] > 0 ||
		signalTypes[SignalAcceptMismatch] > 0 ||
		signalTypes[SignalTLSVersionMismatch] > 0
	botCorroboration := signalTypes[SignalBotUA] > 0 ||
		signalTypes[SignalSuspiciousUA] > 0 ||
		signalTypes[SignalRequestTimingRegular] > 0 ||
		signalTypes[SignalPathEntropyLow] > 0 ||
		signalTypes[SignalPathSeqIDs] > 0 ||
		signalTypes[SignalJA4Rotation] > 0
	if signalTypes[SignalPathEntropyLow] > 0 || signalTypes[SignalPathSeqIDs] > 0 || signalTypes[SignalAlphaSequence] > 0 || signalTypes[SignalBotUA] > 0 {
		return BotCategoryScraper
	}
	if browserShapeAnomaly && botCorroboration {
		return BotCategoryScraper
	}

	// Metronomic request timing alone is weak (some legitimate polling
	// clients are regular too), so require it alongside a bot-ish UA
	// signal rather than letting it trigger scraper categorization by
	// itself.
	if signalTypes[SignalRequestTimingRegular] > 0 &&
		(signalTypes[SignalBotUA] > 0 || signalTypes[SignalSuspiciousUA] > 0 || signalTypes[SignalMissingSecCH] > 0 || signalTypes[SignalMissingSecFetch] > 0) {
		return BotCategoryScraper
	}

	// JA4/JA4H rotation alone can be explained by shared NAT/corporate
	// egress IPs with multiple genuine users, so require it alongside
	// header-order or missing-header anomalies (which a shared-IP
	// population of real browsers wouldn't collectively produce).
	if signalTypes[SignalJA4Rotation] > 0 &&
		(signalTypes[SignalHeaderOrderAnomaly] > 0 || signalTypes[SignalMissingSecCH] > 0 || signalTypes[SignalMissingSecFetch] > 0) {
		return BotCategoryScraper
	}

	// Path alpha sequences strongly indicate systematic AI crawling (aa/ab/ac)
	if signalTypes[SignalAlphaSequence] > 0 {
		return BotCategoryAICrawlerUnknown
	}

	// DDoS patterns: high frequency + multiple sources
	if signalTypes[SignalHighFrequency] > 0 && len(sources) >= 2 {
		return BotCategoryDDoS
	}

	// Scanner patterns: honeypot hits + suspicious UA + no cookies
	if signalTypes[SignalHoneypot] > 0 &&
		signalTypes[SignalSuspiciousUA] > 0 &&
		signalTypes[SignalNoCookies] > 0 {
		return BotCategoryScanner
	}

	// Scraper patterns: no cookies + no referer + missing accept headers + bot-like UA
	// Require bot UA to avoid false positives on legitimate API clients
	if signalTypes[SignalNoCookies] > 0 &&
		signalTypes[SignalNoReferer] > 0 &&
		(signalTypes[SignalMissingAcceptLang] > 0 || signalTypes[SignalMissingAcceptEnc] > 0) &&
		(signalTypes[SignalBotUA] > 0 || signalTypes[SignalSuspiciousUA] > 0) {
		return BotCategoryScraper
	}

	// Proxy/Bot patterns: high proxy lag suggests automated tools or proxies
	// Combined with other signals, high proxy lag is a strong bot indicator
	if signalTypes[SignalProxyLag] > 0 {
		// If combined with script patterns in UA, categorize as script bot
		if strings.Contains(ua, "python") || strings.Contains(ua, "curl") ||
			strings.Contains(ua, "wget") || strings.Contains(ua, "go-http") {
			return BotCategoryScript
		}
		// If combined with missing headers AND bot-like behavior, likely a scraper behind proxy
		// Don't flag as scraper without additional bot indicators (avoid false positives on slow API clients)
		if (signalTypes[SignalNoCookies] > 0 || signalTypes[SignalNoReferer] > 0) &&
			(signalTypes[SignalBotUA] > 0 || signalTypes[SignalHighFrequency] > 0) {
			return BotCategoryScraper
		}
		// If combined with suspicious UA, likely scanner
		if signalTypes[SignalSuspiciousUA] > 0 {
			return BotCategoryScanner
		}
		// If combined with high frequency, could be DDoS
		if signalTypes[SignalHighFrequency] > 0 {
			return BotCategoryDDoS
		}
	}

	// Malicious patterns: multiple high-severity signals
	highSeverityCount := signalTypes[SignalHoneypot] +
		signalTypes[SignalNumericSequence] +
		signalTypes[SignalAlphaSequence] +
		signalTypes[SignalJA4TAbuse]
	if highSeverityCount >= 2 {
		return BotCategoryMalicious
	}

	return BotCategoryUnknown
}
