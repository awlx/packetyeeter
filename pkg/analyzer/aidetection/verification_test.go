package aidetection

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

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
	if status != VerificationFailed {
		t.Fatalf("expected failed verification on resolver error, got %s", status)
	}
	if resolver.addrCalls != 1 {
		t.Fatalf("expected exactly one reverse DNS lookup, got %d", resolver.addrCalls)
	}
}
