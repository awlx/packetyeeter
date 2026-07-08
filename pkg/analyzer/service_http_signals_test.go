package analyzer

import "testing"

// These tests cover the pure predicate helpers backing the HAProxy/SPOE
// signal enrichment (Accept header, Sec-Fetch-*, TLS version) added
// alongside expanded HTTPContext fields. Each predicate is deliberately
// factored out of processHTTPRequest so it can be tested directly against
// realistic browser/bot fixtures without needing a full Analyzer/engine.

func TestIsChromeFamilyUA(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want bool
	}{
		{"chrome desktop", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", true},
		{"chrome ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.114 Mobile/15E148 Safari/604.1", true},
		{"edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67", true},
		{"firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0", false},
		{"safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", false},
		{"curl", "curl/8.4.0", false},
		{"empty", "", false},
		{"googlebot smartphone crawler", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", false},
		{"facebook external hit", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", false},
		{"bingbot chrome-embedded", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.5845.187 Safari/537.36", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isChromeFamilyUA(tc.ua); got != tc.want {
				t.Errorf("isChromeFamilyUA(%q) = %v, want %v", tc.ua, got, tc.want)
			}
		})
	}
}

func TestIsKnownHonestUA(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want bool
	}{
		{"googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
		{"facebook external hit", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", true},
		{"ia_archiver", "ia_archiver (+http://www.alexa.com/site/help/webmasters)", true},
		{"generic crawler keyword", "SomeCustomCrawler/1.0", true},
		{"real chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isKnownHonestUA(tc.ua); got != tc.want {
				t.Errorf("isKnownHonestUA(%q) = %v, want %v", tc.ua, got, tc.want)
			}
		})
	}
}

func TestIsBlinkEngineUA(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want bool
	}{
		{"chrome desktop", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", true},
		{"chrome android", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36", true},
		{"edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67", true},
		{"chrome ios (WebKit-based, not Blink)", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.114 Mobile/15E148 Safari/604.1", false},
		{"firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0", false},
		{"safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", false},
		{"googlebot smartphone crawler", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBlinkEngineUA(tc.ua); got != tc.want {
				t.Errorf("isBlinkEngineUA(%q) = %v, want %v", tc.ua, got, tc.want)
			}
		})
	}
}

func TestIsMissingSecCH(t *testing.T) {
	cases := []struct {
		name             string
		blinkUA          bool
		headerOrderLower string
		want             bool
	}{
		{"chrome with sec-ch-ua", true, "host,sec-ch-ua,accept,user-agent", false},
		{"chrome without sec-ch-ua", true, "host,accept,user-agent", true},
		{"non-blink without sec-ch-ua", false, "host,accept,user-agent", false},
		{"chrome with empty header order", true, "", false}, // no header order captured at all; don't guess
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMissingSecCH(tc.blinkUA, tc.headerOrderLower); got != tc.want {
				t.Errorf("isMissingSecCH(%v, %q) = %v, want %v", tc.blinkUA, tc.headerOrderLower, got, tc.want)
			}
		})
	}
}

func TestIsMissingSecFetch(t *testing.T) {
	cases := []struct {
		name                                     string
		blinkUA                                  bool
		secFetchSite, secFetchMode, secFetchDest string
		want                                     bool
	}{
		{"chrome with full sec-fetch set", true, "same-origin", "navigate", "document", false},
		{"chrome with only site set", true, "same-origin", "", "", false},
		{"chrome missing all sec-fetch", true, "", "", "", true},
		{"non-blink missing all sec-fetch", false, "", "", "", false},
		{"chrome-ios missing all (not gated, WebKit never sends these)", false, "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isMissingSecFetch(tc.blinkUA, tc.secFetchSite, tc.secFetchMode, tc.secFetchDest)
			if got != tc.want {
				t.Errorf("isMissingSecFetch(%v, %q, %q, %q) = %v, want %v",
					tc.blinkUA, tc.secFetchSite, tc.secFetchMode, tc.secFetchDest, got, tc.want)
			}
		})
	}
}

func TestIsAcceptMismatch(t *testing.T) {
	cases := []struct {
		name     string
		chromeUA bool
		accept   string
		want     bool
	}{
		{"chrome with real accept header", true, "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", false},
		{"chrome with empty accept", true, "", true},
		{"chrome with bare wildcard", true, "*/*", true},
		{"chrome with whitespace-padded wildcard", true, "  */*  ", true},
		{"non-chrome with empty accept (not gated)", false, "", false},
		{"non-chrome with wildcard (not gated)", false, "*/*", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAcceptMismatch(tc.chromeUA, tc.accept); got != tc.want {
				t.Errorf("isAcceptMismatch(%v, %q) = %v, want %v", tc.chromeUA, tc.accept, got, tc.want)
			}
		})
	}
}

func TestIsTLSVersionMismatch(t *testing.T) {
	cases := []struct {
		name       string
		chromeUA   bool
		tlsVersion string
		want       bool
	}{
		{"chrome negotiating TLS 1.3", true, "TLSv1.3", false},
		{"chrome negotiating TLS 1.2", true, "TLSv1.2", false},
		{"chrome negotiating TLS 1.0", true, "TLSv1.0", true},
		{"chrome negotiating TLS 1.1", true, "TLSv1.1", true},
		{"chrome negotiating SSLv3", true, "SSLv3", true},
		{"non-chrome negotiating TLS 1.0 (not gated)", false, "TLSv1.0", false},
		{"chrome with no TLS version (plain HTTP)", true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTLSVersionMismatch(tc.chromeUA, tc.tlsVersion); got != tc.want {
				t.Errorf("isTLSVersionMismatch(%v, %q) = %v, want %v", tc.chromeUA, tc.tlsVersion, got, tc.want)
			}
		})
	}
}
