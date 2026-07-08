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

	for i := 0; i < 500; i++ {
		ip := net.ParseIP(fmt.Sprintf("203.0.113.%d", i%256))
		key := fmt.Sprintf("%s|googlebot-%d", ip.String(), i)
		v.storeVerification(key, VerificationFailed)
		if len(v.cache) > v.maxCacheEntries {
			t.Fatalf("cache grew beyond cap: got %d entries, want <= %d", len(v.cache), v.maxCacheEntries)
		}
	}

	if len(v.cache) != v.maxCacheEntries {
		t.Fatalf("expected cache to settle at cap %d entries, got %d", v.maxCacheEntries, len(v.cache))
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
