package analyzer

import "testing"

func TestIsBrowserHeaderOptionalRequest(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		path      string
		accept    string
		userAgent string
		expect    bool
	}{
		{name: "doh endpoint", method: "POST", path: "/dns-query", accept: "application/dns-message", expect: true},
		{name: "dnscrypt proxy", method: "POST", path: "/anything", userAgent: "dnscrypt-proxy", expect: true},
		{name: "health check", method: "GET", path: "/health-gcore", expect: true},
		{name: "websocket", method: "GET", path: "/xmpp-websocket", expect: true},
		{name: "json api", method: "GET", path: "/data/meshviewer.json", expect: true},
		{name: "post wildcard api", method: "POST", path: "/api/query", accept: "*/*", expect: true},
		{name: "normal page", method: "GET", path: "/wiki/start", accept: "text/html", expect: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isBrowserHeaderOptionalRequest(tc.method, tc.path, tc.accept, tc.userAgent)
			if got != tc.expect {
				t.Fatalf("expected %v, got %v", tc.expect, got)
			}
		})
	}
}
