package analyzer

import (
	"PacketYeeter/pkg/analyzer/aidetection"
	"testing"
)

func TestIsBrowserHeaderOptionalRequest(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		host      string
		path      string
		accept    string
		userAgent string
		expect    bool
	}{
		{name: "doh endpoint", method: "POST", path: "/dns-query", accept: "application/dns-message", expect: true},
		{name: "doh query alias on doh host", method: "GET", host: "doh.example.net", path: "/query", expect: true},
		{name: "dnscrypt proxy", method: "POST", path: "/anything", userAgent: "dnscrypt-proxy", expect: true},
		{name: "health check", method: "GET", path: "/health-gcore", expect: true},
		{name: "websocket", method: "GET", path: "/xmpp-websocket", expect: true},
		{name: "json api", method: "GET", path: "/data/meshviewer.json", expect: true},
		{name: "api endpoint", method: "GET", path: "/api/status", expect: true},
		{name: "background task endpoint", method: "GET", path: "/wiki/lib/exe/taskrunner.php", expect: true},
		{name: "static asset", method: "GET", path: "/sounds/outgoingRinging.wav", expect: true},
		{name: "post wildcard api", method: "POST", path: "/api/query", accept: "*/*", expect: true},
		{name: "normal page", method: "GET", path: "/wiki/start", accept: "text/html", expect: false},
		{name: "query path on normal host", method: "GET", host: "www.example.net", path: "/query", expect: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isBrowserHeaderOptionalRequest(tc.method, tc.host, tc.path, tc.accept, tc.userAgent)
			if got != tc.expect {
				t.Fatalf("expected %v, got %v", tc.expect, got)
			}
		})
	}
}

func TestIsProtocolOrBackgroundRequest(t *testing.T) {
	if !isProtocolOrBackgroundRequest("GET", "doh.example.net", "/dns-query", "", "") {
		t.Fatal("expected DoH request to be protocol/background")
	}
	if !isProtocolOrBackgroundRequest("GET", "", "/app.js", "", "") {
		t.Fatal("expected static asset to be protocol/background")
	}
	if isProtocolOrBackgroundRequest("GET", "", "/wiki/start", "text/html", "") {
		t.Fatal("expected normal HTML page to keep entropy/header checks")
	}
}

// TestJA4MatchSignalGatesOnExactMatch verifies that a JA4DB "wildcard_tls"
// match (which only shares the coarse JA4 prefix with an unrelated entry,
// see ja4db.ja4WildcardPrefix) is never classified as a browser signal and
// never carries ja4_info - both of which would otherwise let an
// attacker-crafted fingerprint that merely collides on the coarse prefix
// impersonate a browser and evade bot detection.
func TestJA4MatchSignalGatesOnExactMatch(t *testing.T) {
	cases := []struct {
		name               string
		isBrowser          bool
		matchType          string
		wantSigType        aidetection.SignalType
		wantWeight         float64
		wantIncludeJA4Info bool
	}{
		{
			name:               "exact browser match: browser signal with ja4_info",
			isBrowser:          true,
			matchType:          "exact",
			wantSigType:        aidetection.SignalBrowserDetected,
			wantWeight:         1.0,
			wantIncludeJA4Info: true,
		},
		{
			name:               "wildcard browser-looking match: NOT a browser signal, no ja4_info",
			isBrowser:          true,
			matchType:          "wildcard_tls",
			wantSigType:        aidetection.SignalJA4HBotMatch,
			wantWeight:         20.0,
			wantIncludeJA4Info: false,
		},
		{
			name:               "exact non-browser match: bot-match signal with ja4_info",
			isBrowser:          false,
			matchType:          "exact",
			wantSigType:        aidetection.SignalJA4HBotMatch,
			wantWeight:         20.0,
			wantIncludeJA4Info: true,
		},
		{
			name:               "wildcard non-browser match: bot-match signal, no ja4_info",
			isBrowser:          false,
			matchType:          "wildcard_tls",
			wantSigType:        aidetection.SignalJA4HBotMatch,
			wantWeight:         20.0,
			wantIncludeJA4Info: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigType, weight, includeJA4Info := ja4MatchSignal(tc.isBrowser, tc.matchType)
			if sigType != tc.wantSigType {
				t.Errorf("sigType = %v, want %v", sigType, tc.wantSigType)
			}
			if weight != tc.wantWeight {
				t.Errorf("weight = %v, want %v", weight, tc.wantWeight)
			}
			if includeJA4Info != tc.wantIncludeJA4Info {
				t.Errorf("includeJA4Info = %v, want %v", includeJA4Info, tc.wantIncludeJA4Info)
			}
		})
	}
}
