package analyzer

import (
	"encoding/json"
	"net/http"
	"strconv"

	"PacketYeeter/pkg/analyzer/sustained"
)

// registerEnforcementInspectorHandlers exposes the analyzer-wide runtime
// enforcement kill switch.
//
// It is analyzer-wide on purpose. The situation it exists for is "we are
// blocking traffic we should not be, right now", which is never known up front
// to be confined to one detector, so an operator should not have to identify
// the responsible detector before they can stop it.
func registerEnforcementInspectorHandlers(a *Analyzer, mux *http.ServeMux) {
	mux.HandleFunc("/api/enforcement", func(w http.ResponseWriter, r *http.Request) {
		stopped, reason := a.EnforcementStopped()
		writeJSON(w, struct {
			Enforcing  bool   `json:"enforcing"`
			DryRun     bool   `json:"dry_run"`
			Stopped    bool   `json:"stopped"`
			StopReason string `json:"stop_reason,omitempty"`
		}{
			Enforcing:  a.Enforcing(),
			DryRun:     a.Config.DryRun,
			Stopped:    stopped,
			StopReason: reason,
		})
	})

	// Mutating, so it goes through the same same-origin guard as every other
	// state-changing inspector endpoint. One-way by design: stopping has to be
	// possible in seconds, while resuming should go through a config change and
	// a restart, which leaves a record.
	mux.HandleFunc("/api/enforcement/stop", a.sameOriginOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Reason string `json:"reason"`
		}
		// An empty body is accepted: during an incident an operator should not
		// have to get the payload right before they can stop enforcing.
		_ = json.NewDecoder(r.Body).Decode(&req)

		a.StopEnforcement(req.Reason)

		writeJSON(w, map[string]string{
			"status":  "ok",
			"message": "enforcement stopped; detection continues. Resuming requires a config change and a restart.",
		})
	}))
}

// registerSustainedInspectorHandlers exposes sustained-download state.
//
// Detection that runs on a sliding window is only tunable if the window itself
// is visible: a threshold set from guesswork will either never fire or sweep up
// ordinary traffic, and neither failure is obvious from a block count.
func registerSustainedInspectorHandlers(a *Analyzer, mux *http.ServeMux) {
	mux.HandleFunc("/api/sustained", func(w http.ResponseWriter, r *http.Request) {
		if a.Sustained == nil {
			writeJSON(w, map[string]interface{}{"enabled": false})
			return
		}

		limit := 25
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		stopped, reason := a.EnforcementStopped()
		enforcing := a.Sustained.Enforcing() && a.Enforcing()

		writeJSON(w, struct {
			Enabled            bool                       `json:"enabled"`
			Enforcing          bool                       `json:"enforcing"`
			DryRun             bool                       `json:"dry_run"`
			EnforcementStopped bool                       `json:"enforcement_stopped"`
			StopReason         string                     `json:"stop_reason,omitempty"`
			Config             sustained.Config           `json:"config"`
			Stats              sustained.Stats            `json:"stats"`
			Clients            []sustained.ClientSnapshot `json:"clients"`
		}{
			Enabled:            true,
			Enforcing:          enforcing,
			DryRun:             a.Config.DryRun,
			EnforcementStopped: stopped,
			StopReason:         reason,
			Config:             a.Sustained.Settings(),
			Stats:              a.Sustained.Stats(),
			Clients:            a.Sustained.Snapshot(limit, r.URL.Query().Get("by"), enforcing),
		})
	})
}
