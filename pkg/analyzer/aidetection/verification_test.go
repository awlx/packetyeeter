package aidetection

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// fakeClock lets tests control the passage of time seen by CrawlerVerifier
// without sleeping, so TTL/eviction behavior can be tested deterministically.
type fakeClock struct {
	t time.Time
}

func (c *fakeClock) now() time.Time {
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.t = c.t.Add(d)
}

func TestCategorizeBotBrowserInfo(t *testing.T) {
	v := NewCrawlerVerifier(nil)
	cat := v.CategorizeBot("", "", "", "", "Chrome 120 on Windows", map[SignalType]int{}, map[SignalSource]int{}, VerificationUnknown)
	if cat != BotCategoryBrowser {
		t.Fatalf("expected browser category, got %v", cat)
	}

	cat = v.CategorizeBot("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "", "", "", "", map[SignalType]int{}, map[SignalSource]int{}, VerificationUnknown)
	if cat != BotCategoryBrowser {
		t.Fatalf("expected browser category from UA, got %v", cat)
	}
}

// TestCategorizeBotRequestTimingRegularRequiresBotSignal verifies that
// metronomic request timing alone (no other bot indicators) is NOT enough
// to categorize traffic as a scraper - a legitimate regular-polling client
// (e.g. a status-page widget) shouldn't be flagged on timing regularity by
// itself. It must combine with a bot-ish UA/header anomaly signal.
func TestCategorizeBotRequestTimingRegularRequiresBotSignal(t *testing.T) {
	v := NewCrawlerVerifier(nil)

	// Timing regularity alone: no scraper category.
	cat := v.CategorizeBot("", "", "", "", "", map[SignalType]int{
		SignalRequestTimingRegular: 5,
	}, map[SignalSource]int{}, VerificationUnknown)
	if cat == BotCategoryScraper {
		t.Fatalf("expected timing regularity alone to NOT trigger scraper category, got %v", cat)
	}

	// Timing regularity + bot UA: scraper category.
	cat = v.CategorizeBot("", "", "", "", "", map[SignalType]int{
		SignalRequestTimingRegular: 5,
		SignalBotUA:                1,
	}, map[SignalSource]int{}, VerificationUnknown)
	if cat != BotCategoryScraper {
		t.Fatalf("expected timing regularity + bot UA to trigger scraper category, got %v", cat)
	}
}

// TestCategorizeBotJA4RotationRequiresHeaderAnomaly verifies JA4/JA4H
// fingerprint rotation alone (which can be explained by a shared NAT/proxy
// IP with multiple genuine browsers) doesn't trigger scraper categorization
// without an accompanying header-order/missing-header anomaly.
func TestCategorizeBotJA4RotationRequiresHeaderAnomaly(t *testing.T) {
	v := NewCrawlerVerifier(nil)

	cat := v.CategorizeBot("", "", "", "", "", map[SignalType]int{
		SignalJA4Rotation: 3,
	}, map[SignalSource]int{}, VerificationUnknown)
	if cat == BotCategoryScraper {
		t.Fatalf("expected JA4 rotation alone to NOT trigger scraper category, got %v", cat)
	}

	cat = v.CategorizeBot("", "", "", "", "", map[SignalType]int{
		SignalJA4Rotation:        3,
		SignalHeaderOrderAnomaly: 1,
	}, map[SignalSource]int{}, VerificationUnknown)
	if cat != BotCategoryScraper {
		t.Fatalf("expected JA4 rotation + header order anomaly to trigger scraper category, got %v", cat)
	}
}

func TestCategorizeBotBrowserShapeAnomalyRequiresCorroboration(t *testing.T) {
	v := NewCrawlerVerifier(nil)

	cat := v.CategorizeBot("", "", "", "", "", map[SignalType]int{
		SignalMissingSecCH:    1,
		SignalMissingSecFetch: 1,
		SignalAcceptMismatch:  1,
	}, map[SignalSource]int{}, VerificationUnknown)
	if cat == BotCategoryScraper {
		t.Fatalf("expected browser-shape anomalies without corroboration to NOT trigger scraper category, got %v", cat)
	}

	cat = v.CategorizeBot("", "", "", "", "", map[SignalType]int{
		SignalMissingSecFetch:      1,
		SignalRequestTimingRegular: 3,
	}, map[SignalSource]int{}, VerificationUnknown)
	if cat != BotCategoryScraper {
		t.Fatalf("expected browser-shape anomaly plus timing corroboration to trigger scraper category, got %v", cat)
	}
}

func TestIsBrowserInfo(t *testing.T) {
	if !IsBrowserInfo("chrome 120 [verified]") {
		t.Fatalf("expected chrome to be browser info")
	}
	if IsBrowserInfo("headlesschrome 120") {
		t.Fatalf("expected headlesschrome to be ignored")
	}
}

type fakeCrawlerResolver struct {
	addrCalls int
	ipCalls   int
	names     []string
	ips       []net.IPAddr
	err       error
}

func (r *fakeCrawlerResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	r.addrCalls++
	if r.err != nil {
		return nil, r.err
	}
	return r.names, nil
}

func (r *fakeCrawlerResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	r.ipCalls++
	if r.err != nil {
		return nil, r.err
	}
	return r.ips, nil
}

func TestVerifyCrawlerUsesResolverAndCaches(t *testing.T) {
	ip := net.ParseIP("66.249.66.1")
	resolver := &fakeCrawlerResolver{
		names: []string{"crawl-66-249-66-1.googlebot.com."},
		ips:   []net.IPAddr{{IP: ip}},
	}
	v := newCrawlerVerifier(nil, resolver, time.Second, time.Minute)
	v.verifiedDomains["googlebot"] = []string{".googlebot.com."}

	status := v.VerifyCrawler(ip, "Mozilla/5.0 Googlebot/2.1")
	if status != VerificationVerified {
		t.Fatalf("expected verified crawler, got %s", status)
	}
	status = v.VerifyCrawler(ip, "Mozilla/5.0 Googlebot/2.1")
	if status != VerificationVerified {
		t.Fatalf("expected cached verified crawler, got %s", status)
	}
	if resolver.addrCalls != 1 || resolver.ipCalls != 1 {
		t.Fatalf("expected cached verification to avoid duplicate DNS lookups, got reverse=%d forward=%d", resolver.addrCalls, resolver.ipCalls)
	}
}

func TestVerifyCrawlerResolverFailureIsDeterministic(t *testing.T) {
	resolver := &fakeCrawlerResolver{err: errors.New("dns timeout")}
	v := newCrawlerVerifier(nil, resolver, time.Nanosecond, time.Minute)

	status := v.VerifyCrawler(net.ParseIP("192.0.2.10"), "Googlebot/2.1")
	if status != VerificationUnknown {
		t.Fatalf("expected unknown verification on resolver error (no PTR isn't evidence of anything), got %s", status)
	}
	if resolver.addrCalls != 1 {
		t.Fatalf("expected exactly one reverse DNS lookup, got %d", resolver.addrCalls)
	}
}

// TestVerificationCacheRespectsSizeCap ensures that generating a large
// number of unique (IP, claimed-bot) cache keys cannot grow the cache
// beyond its configured maximum size, which protects against a memory
// exhaustion attack via unbounded unique-key generation.
func TestVerificationCacheRespectsSizeCap(t *testing.T) {
	resolver := &fakeCrawlerResolver{err: errors.New("dns timeout")}
	v := newCrawlerVerifier(nil, resolver, time.Second, time.Minute)
	v.maxCacheEntries = 50

	reachedCap := false
	sawHeadroomAfterCap := false
	for i := range 500 {
		ip := net.ParseIP(fmt.Sprintf("203.0.113.%d", i%256))
		key := fmt.Sprintf("%s|googlebot-%d", ip.String(), i)
		v.storeVerification(key, VerificationFailed)
		if len(v.cache) > v.maxCacheEntries {
			t.Fatalf("cache grew beyond cap: got %d entries, want <= %d", len(v.cache), v.maxCacheEntries)
		}
		if len(v.cache) >= v.maxCacheEntries {
			reachedCap = true
		}
		// Batch eviction drops the cache below the cap once it fills, so the O(n)
		// oldest-scan runs once per ~cap/10 inserts instead of on every insert.
		// One-at-a-time eviction would keep it pinned exactly at the cap forever.
		if reachedCap && len(v.cache) < v.maxCacheEntries {
			sawHeadroomAfterCap = true
		}
	}

	if !sawHeadroomAfterCap {
		t.Fatal("expected batch eviction to leave headroom below the cap after filling; cache stayed pinned at cap (per-insert eviction)")
	}
	if len(v.cache) < v.maxCacheEntries-v.maxCacheEntries/10-1 {
		t.Fatalf("cache evicted too aggressively: got %d entries, want >= %d", len(v.cache), v.maxCacheEntries-v.maxCacheEntries/10-1)
	}
}

// TestNegativeVerificationExpiresBeforePositiveTTL demonstrates that an
// unresolved/negative verification result is cached for a much shorter TTL
// than a successful one, so a transient DNS failure or a not-yet-configured
// PTR record (or an attacker poisoning the cache for a victim IP) self-heals
// and a legitimate crawler is re-verified well before the full positive-
// result TTL would elapse.
func TestNegativeVerificationExpiresBeforePositiveTTL(t *testing.T) {
	ip := net.ParseIP("66.249.66.5")
	resolver := &fakeCrawlerResolver{err: errors.New("dns timeout")}
	// Long positive TTL so we can clearly observe the negative TTL expiring
	// well before it, while sharing the same cacheKey.
	v := newCrawlerVerifier(nil, resolver, time.Second, 10*time.Minute)

	clock := &fakeClock{t: time.Now()}
	v.now = clock.now

	// First request can't complete DNS verification (negative/unknown cache entry).
	status := v.VerifyCrawler(ip, "Mozilla/5.0 Googlebot/2.1")
	if status != VerificationUnknown {
		t.Fatalf("expected initial verification to be unknown, got %s", status)
	}
	if resolver.addrCalls != 1 {
		t.Fatalf("expected one reverse DNS lookup, got %d", resolver.addrCalls)
	}

	// Advance time past the negative TTL but well short of the positive TTL.
	clock.advance(negativeVerificationCacheTTL + time.Second)

	// The transient failure has "healed" (DNS now resolves correctly), and
	// because the negative entry expired quickly, the legitimate crawler is
	// re-verified rather than being stuck with the stale unknown result.
	resolver.err = nil
	resolver.names = []string{"crawl-66-249-66-5.googlebot.com."}
	resolver.ips = []net.IPAddr{{IP: ip}}
	v.verifiedDomains["googlebot"] = []string{".googlebot.com."}

	status = v.VerifyCrawler(ip, "Mozilla/5.0 Googlebot/2.1")
	if status != VerificationVerified {
		t.Fatalf("expected re-verification to succeed after negative TTL expiry, got %s", status)
	}
	if resolver.addrCalls != 2 {
		t.Fatalf("expected negative cache entry to expire and trigger a second lookup, got %d calls", resolver.addrCalls)
	}
}

// TestVerifyCrawlerPTRMismatchIsFailed verifies that a PTR record which
// *does* resolve, but to a hostname that doesn't match any domain expected
// for the claimed crawler, is still treated as an active verification
// failure (distinct from the "no PTR at all" case above) since it's a much
// stronger signal that the user agent's crawler claim doesn't match reality.
func TestVerifyCrawlerPTRMismatchIsFailed(t *testing.T) {
	ip := net.ParseIP("203.0.113.50")
	resolver := &fakeCrawlerResolver{names: []string{"some-other-host.example.net."}}
	v := newCrawlerVerifier(nil, resolver, time.Second, time.Minute)

	status := v.VerifyCrawler(ip, "Mozilla/5.0 Googlebot/2.1")
	if status != VerificationFailed {
		t.Fatalf("expected a PTR record resolving to an unrelated domain to be a verification failure, got %s", status)
	}
}

// TestVerifyCrawlerSEMrushBotIsVerifiable ensures SEMrushBot - a widely used,
// well-documented SEO crawler that publishes reverse-DNS verification just
// like the major search engines - is recognized and can be positively
// verified via PTR lookup, instead of being silently skipped (no dampening)
// as it was in production before this fix.
func TestVerifyCrawlerSEMrushBotIsVerifiable(t *testing.T) {
	ip := net.ParseIP("194.35.188.225")
	resolver := &fakeCrawlerResolver{
		names: []string{"crawl.semrush.com."},
		ips:   []net.IPAddr{{IP: ip}},
	}
	v := newCrawlerVerifier(nil, resolver, time.Second, time.Minute)

	status := v.VerifyCrawler(ip, "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)")
	if status != VerificationVerified {
		t.Fatalf("expected SEMrushBot to be verifiable via PTR, got %s", status)
	}
}
