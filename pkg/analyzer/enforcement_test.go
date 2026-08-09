package analyzer

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiv1 "PacketYeeter/api/proto/v1"
)

func newEnforcementMux(a *Analyzer) *http.ServeMux {
	mux := http.NewServeMux()
	registerEnforcementInspectorHandlers(a, mux)
	return mux
}

func postStop(mux *http.ServeMux, body string, origin string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/enforcement/stop", reader)
	req.Host = "127.0.0.1:9092"
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestEnforcementKillSwitchStopsBlockCommands(t *testing.T) {
	a := &Analyzer{}
	mux := newEnforcementMux(a)

	if !a.Enforcing() {
		t.Fatal("Enforcing = false before the kill switch")
	}

	rec := postStop(mux, `{"reason":"incident 123"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	if a.Enforcing() {
		t.Fatal("Enforcing = true after the kill switch")
	}
	stopped, reason := a.EnforcementStopped()
	if !stopped || reason != "incident 123" {
		t.Fatalf("EnforcementStopped = %v, %q", stopped, reason)
	}

	block := &apiv1.Command{Type: apiv1.CommandType_COMMAND_BLOCK_IP, Ip: net.ParseIP("192.0.2.1").To4()}
	if !a.suppressedByKillSwitch(block) {
		t.Fatal("block command not suppressed after the kill switch")
	}
}

// The kill switch is pulled precisely when something is being blocked that
// should not be, so the commands that undo a block must keep flowing.
func TestEnforcementKillSwitchLetsRelievingCommandsThrough(t *testing.T) {
	a := &Analyzer{}
	a.StopEnforcement("incident")

	relieving := []apiv1.CommandType{
		apiv1.CommandType_COMMAND_UNBLOCK_IP,
		apiv1.CommandType_COMMAND_UNBLOCK_CIDR,
		apiv1.CommandType_COMMAND_ALLOWLIST_IP,
		apiv1.CommandType_COMMAND_REMOVE_ALLOWLIST_IP,
	}
	for _, cmdType := range relieving {
		cmd := &apiv1.Command{Type: cmdType, Ip: net.ParseIP("192.0.2.1").To4()}
		if a.suppressedByKillSwitch(cmd) {
			t.Fatalf("%v suppressed; relieving commands must still be issued", cmdType)
		}
	}

	block := &apiv1.Command{Type: apiv1.CommandType_COMMAND_BLOCK_CIDR}
	if !a.suppressedByKillSwitch(block) {
		t.Fatal("BLOCK_CIDR not suppressed")
	}
}

func TestEnforcementKillSwitchAcceptsEmptyBody(t *testing.T) {
	a := &Analyzer{}
	mux := newEnforcementMux(a)

	// During an incident an operator should not have to get the payload right
	// before they can stop enforcing.
	if rec := postStop(mux, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	stopped, reason := a.EnforcementStopped()
	if !stopped || reason == "" {
		t.Fatalf("EnforcementStopped = %v, %q; want a placeholder reason", stopped, reason)
	}
}

func TestEnforcementKillSwitchRejectsCrossOrigin(t *testing.T) {
	a := &Analyzer{}
	mux := newEnforcementMux(a)

	rec := postStop(mux, `{"reason":"x"}`, "https://attacker.example")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !a.Enforcing() {
		t.Fatal("cross-origin request stopped enforcement")
	}
}

func TestEnforcementKillSwitchRejectsNonPost(t *testing.T) {
	a := &Analyzer{}
	mux := newEnforcementMux(a)

	req := httptest.NewRequest(http.MethodGet, "/api/enforcement/stop", nil)
	req.Host = "127.0.0.1:9092"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if !a.Enforcing() {
		t.Fatal("GET stopped enforcement")
	}
}

func TestEnforcementStatusReportsDryRun(t *testing.T) {
	a := &Analyzer{Config: Config{DryRun: true}}
	mux := newEnforcementMux(a)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enforcement", nil))

	var body struct {
		Enforcing bool `json:"enforcing"`
		DryRun    bool `json:"dry_run"`
		Stopped   bool `json:"stopped"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Enforcing || !body.DryRun || body.Stopped {
		t.Fatalf("body = %+v; want not enforcing due to dry-run, kill switch untouched", body)
	}
}
