package analyzer

import "testing"

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
