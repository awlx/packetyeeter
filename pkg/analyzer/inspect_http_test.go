package analyzer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubOK is a minimal downstream handler used to observe whether
// sameOriginOnly let a request through.
func stubOK(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestIsLoopbackHostname(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"127.0.0.1", true},
		{"127.0.0.53", true}, // any loopback IP, not just 127.0.0.1
		{"::1", true},
		{"", false},
		{"evil.example.com", false},
		{"attacker-controlled-localhost.com", false},
		{"10.0.0.5", false}, // private but not loopback
		{"0.0.0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			if got := isLoopbackHostname(tc.host); got != tc.want {
				t.Errorf("isLoopbackHostname(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// TestSameOriginOnly covers the CSRF/DNS-rebinding guard applied to the
// inspector's state-mutating routes (W8): a malicious cross-origin page must
// not be able to fire a side effect via a CORS-simple request, and a
// DNS-rebound hostname must not be able to reach the loopback-only inspector.
func TestSameOriginOnly(t *testing.T) {
	handler := sameOriginOnly(stubOK)

	t.Run("same-origin request with no Origin/Referer is allowed (curl/tooling)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9092/api/feedback/allowlist/bulk-delete", nil)
		req.Host = "127.0.0.1:9092"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("same-origin request with matching Origin is allowed (inspector UI)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9092/api/feedback/allowlist/bulk-delete", nil)
		req.Host = "127.0.0.1:9092"
		req.Header.Set("Origin", "http://127.0.0.1:9092")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("loopback Origin on a different loopback port is allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9092/api/sessions/delete", nil)
		req.Host = "127.0.0.1:9092"
		req.Header.Set("Origin", "http://localhost:8080")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("IPv6 loopback Host is allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://[::1]:9092/api/sessions/delete", nil)
		req.Host = "[::1]:9092"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("cross-origin Origin is rejected (CSRF)", func(t *testing.T) {
		// This is the CORS-simple-request CSRF path from W8: a malicious
		// page the operator has open in another tab fires a cross-origin
		// POST at the inspector.
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9092/api/feedback/allowlist/bulk-delete", nil)
		req.Host = "127.0.0.1:9092"
		req.Header.Set("Origin", "https://evil.example.com")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("cross-origin Referer with no Origin is rejected (CSRF)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9092/api/feedback/learning/clear", nil)
		req.Host = "127.0.0.1:9092"
		req.Header.Set("Referer", "https://evil.example.com/attack.html")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("DNS-rebound Host is rejected even with no Origin/Referer", func(t *testing.T) {
		// A DNS-rebinding attacker points a hostname they control at
		// 127.0.0.1; the browser's Host header carries their hostname, not
		// "localhost"/a loopback literal.
		req := httptest.NewRequest(http.MethodPost, "http://attacker.example.com:9092/api/labels/delete", nil)
		req.Host = "attacker.example.com:9092"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("DNS-rebound Host is rejected even with a loopback Origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://attacker.example.com:9092/api/labels/delete", nil)
		req.Host = "attacker.example.com:9092"
		req.Header.Set("Origin", "http://127.0.0.1:9092")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})
}
