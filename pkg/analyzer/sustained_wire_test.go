package analyzer

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/sustained"
)

func TestSustainedHooksAreNilSafeWhenDisabled(t *testing.T) {
	a := &Analyzer{}

	// Every hook has to tolerate a nil tracker, because the feature defaults to
	// off and the hooks sit on the SPOE hot path.
	a.observeSustainedRequest(net.ParseIP("192.0.2.1"), &apiv1.HTTPContext{Host: "example.test", Path: "/a/b"})
	a.observeSustainedBytes(&apiv1.Signal{EgressContext: &apiv1.EgressContext{BytesDelta: 1 << 20}}, net.ParseIP("192.0.2.1"))
	a.markSustainedVerifiedBot(net.ParseIP("192.0.2.1"))
}

func TestVerifiedBotSetExpires(t *testing.T) {
	set := newVerifiedBotSet()
	start := time.Now()

	set.mark("192.0.2.1", start)
	if !set.contains("192.0.2.1", start) {
		t.Fatal("freshly marked client not reported as verified")
	}
	if set.contains("192.0.2.2", start) {
		t.Fatal("unmarked client reported as verified")
	}

	lapsed := start.Add(verifiedBotTTL)
	if set.contains("192.0.2.1", lapsed) {
		t.Fatal("verification did not lapse at the TTL")
	}

	set.prune(lapsed)
	set.mu.RLock()
	remaining := len(set.entries)
	set.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("entries after prune = %d, want 0", remaining)
	}
}

func TestObserveSustainedRequestReachesTracker(t *testing.T) {
	cfg := sustained.DefaultConfig()
	cfg.Enabled = true
	a := &Analyzer{Sustained: sustained.New(cfg)}

	a.observeSustainedRequest(net.ParseIP("192.0.2.1"), &apiv1.HTTPContext{Host: "example.test", Path: "/a/b"})

	if got := a.Sustained.Stats().TrackedClients; got != 1 {
		t.Fatalf("tracked clients = %d, want 1", got)
	}
}

func TestSustainedInspectorReportsDisabled(t *testing.T) {
	a := &Analyzer{}
	mux := http.NewServeMux()
	registerSustainedInspectorHandlers(a, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/sustained", nil))

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Enabled {
		t.Fatal("enabled = true with no tracker configured")
	}
}
