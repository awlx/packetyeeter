package analyzer

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	aidetection "PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/analyzer/reputation"
	"PacketYeeter/pkg/ml"
)

//go:embed static/inspector.html
var inspectorFS embed.FS

// registerInspectorHandlers registers read-only inspection endpoints on the provided mux.
// loadSessionsFromDisk reads all session recordings from disk
func loadSessionsFromDisk(sessionsDir string) ([]map[string]interface{}, error) {
	files, err := filepath.Glob(filepath.Join(sessionsDir, "recording-*.jsonl"))
	if err != nil {
		return nil, err
	}

	var sessions []map[string]interface{}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var session map[string]interface{}
			if err := json.Unmarshal(scanner.Bytes(), &session); err != nil {
				continue
			}
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

// deleteSessionFromDisk removes a session recording from disk
func deleteSessionFromDisk(sessionsDir, sessionID string) error {
	files, err := filepath.Glob(filepath.Join(sessionsDir, "sessions_*.jsonl"))
	if err != nil {
		return err
	}

	for _, file := range files {
		// Read all sessions
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		var sessions []map[string]interface{}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var session map[string]interface{}
			if err := json.Unmarshal(scanner.Bytes(), &session); err == nil {
				sessions = append(sessions, session)
			}
		}
		f.Close()

		// Filter out the session to delete
		var filtered []map[string]interface{}
		found := false
		for _, s := range sessions {
			if sid, ok := s["SessionID"].(string); ok && sid == sessionID {
				found = true
				continue
			}
			filtered = append(filtered, s)
		}

		if !found {
			continue
		}

		// Rewrite file without the deleted session
		tmpFile := file + ".tmp"
		f, err = os.Create(tmpFile)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(f)
		for _, s := range filtered {
			if err := encoder.Encode(s); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
		return os.Rename(tmpFile, file)
	}

	return fmt.Errorf("session not found: %s", sessionID)
}

func registerInspectorHandlers(a *Analyzer, mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := inspectorFS.ReadFile("static/inspector.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})

	mux.HandleFunc("/api/detections", func(w http.ResponseWriter, r *http.Request) {
		dets := a.AIEngine.GetAllLatestDetections()
		writeJSON(w, formatDetections(dets))
	})

	mux.HandleFunc("/api/detections/verified", func(w http.ResponseWriter, r *http.Request) {
		dets := a.AIEngine.GetVerifiedBots()
		writeJSON(w, formatDetections(dets))
	})

	mux.HandleFunc("/api/detections/history", func(w http.ResponseWriter, r *http.Request) {
		dets := a.AIEngine.GetDetectionHistory(6 * time.Hour)
		writeJSON(w, formatDetections(dets))
	})

	mux.HandleFunc("/api/ip/", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimPrefix(r.URL.Path, "/api/ip/")
		if ip == "" {
			http.Error(w, "ip required", http.StatusBadRequest)
			return
		}
		det := a.AIEngine.GetLatestDetection("ip:" + ip)
		resp := struct {
			Detection  *detectionDTO `json:"detection,omitempty"`
			Reputation float64       `json:"reputation"`
		}{}
		if det != nil {
			dto := formatDetection(det)
			resp.Detection = &dto
		}
		if a.Reputation != nil {
			resp.Reputation = a.Reputation.GetScore(ip, reputation.TypeIP)
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/api/ja4h/", func(w http.ResponseWriter, r *http.Request) {
		fp := strings.TrimPrefix(r.URL.Path, "/api/ja4h/")
		if fp == "" {
			http.Error(w, "ja4h required", http.StatusBadRequest)
			return
		}
		det := a.AIEngine.GetLatestDetection("ja4h:" + fp)
		if det == nil {
			writeJSON(w, nil)
			return
		}
		writeJSON(w, formatDetection(det))
	})

	// Feedback API endpoints
	mux.HandleFunc("/api/feedback/report-fp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP     string   `json:"ip"`
			Reason string   `json:"reason,omitempty"`
			Labels []string `json:"labels,omitempty"` // e.g., ["legitimate_crawler", "cdn", "monitoring_tool"]
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.IP == "" {
			http.Error(w, "ip required", http.StatusBadRequest)
			return
		}
		ipAddr := net.ParseIP(req.IP)
		if ipAddr == nil {
			http.Error(w, "invalid ip address", http.StatusBadRequest)
			return
		}
		// Get detection details if available
		det := a.AIEngine.GetLatestDetection("ip:" + req.IP)
		var asn string
		var confidence float64
		var category aidetection.BotCategory
		var wasBlocked bool
		if det != nil {
			asn = det.ASN
			confidence = det.Confidence
			category = det.BotCategory
			wasBlocked = true

			// Store labels in detection metadata for future reference
			if len(req.Labels) > 0 {
				det.Metadata = map[string]interface{}{
					"fp_labels": req.Labels,
					"fp_reason": req.Reason,
					"fp_time":   time.Now().Format(time.RFC3339),
				}
			}

			// Save to training dataset
			if err := saveLabeledDetection(det, "human", req.Labels, req.Reason); err != nil {
				// Log error but continue
				logrus.WithError(err).Error("Failed to save labeled detection to training dataset")
			}
		}
		a.AIEngine.RecordFalsePositive(ipAddr, asn, confidence, category, wasBlocked)

		// Start recording immediately for this IP
		a.AIEngine.StartRecordingForIP(req.IP, "fp")

		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"message": "false positive recorded for " + req.IP,
			"labels":  req.Labels,
		})
	})

	mux.HandleFunc("/api/feedback/report-tp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP     string `json:"ip"`
			Reason string `json:"reason,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.IP == "" {
			http.Error(w, "ip required", http.StatusBadRequest)
			return
		}
		ipAddr := net.ParseIP(req.IP)
		if ipAddr == nil {
			http.Error(w, "invalid ip address", http.StatusBadRequest)
			return
		}
		// Get detection details if available
		det := a.AIEngine.GetLatestDetection("ip:" + req.IP)
		var asn string
		var confidence float64
		var category aidetection.BotCategory
		var wasBlocked bool
		if det != nil {
			asn = det.ASN
			confidence = det.Confidence
			category = det.BotCategory
			wasBlocked = true

			// Save to training dataset
			botLabels := []string{"malicious"}
			if category != "" {
				botLabels = append(botLabels, string(category))
			}
			if err := saveLabeledDetection(det, "bot", botLabels, req.Reason); err != nil {
				// Log error but continue
				logrus.WithError(err).Error("Failed to save labeled detection to training dataset")
			}
		}
		a.AIEngine.RecordTruePositive(ipAddr, asn, confidence, category, wasBlocked)

		// Start recording immediately for this IP
		a.AIEngine.StartRecordingForIP(req.IP, "tp")

		writeJSON(w, map[string]string{"status": "ok", "message": "true positive recorded for " + req.IP})
	})

	mux.HandleFunc("/api/feedback/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := a.AIEngine.GetFeedbackStats()
		writeJSON(w, stats)
	})

	mux.HandleFunc("/api/feedback/statistics", func(w http.ResponseWriter, r *http.Request) {
		stats := a.AIEngine.GetFeedbackStats()
		writeJSON(w, stats)
	})

	// Get learning window IPs
	mux.HandleFunc("/api/feedback/learning/ips", func(w http.ResponseWriter, r *http.Request) {
		ips := a.AIEngine.GetLearningWindowIPs()
		writeJSON(w, ips)
	})

	// ML model metrics (hybrid model stats)
	mux.HandleFunc("/api/ml/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Get ML model from engine
		if hybridModel, ok := a.AIEngine.GetMLModel().(*ml.HybridModel); ok {
			metrics := hybridModel.GetMetrics()
			writeJSON(w, metrics)
		} else {
			writeJSON(w, map[string]interface{}{
				"model_type": "statistical",
				"has_onnx":   false,
			})
		}
	})

	// Session recordings for ML training (from disk)
	mux.HandleFunc("/api/sessions/list", func(w http.ResponseWriter, r *http.Request) {
		sessions, err := loadSessionsFromDisk("/var/cache/packetyeeter/sessions")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, sessions)
	})

	mux.HandleFunc("/api/sessions/export", func(w http.ResponseWriter, r *http.Request) {
		sessions, err := loadSessionsFromDisk("/var/cache/packetyeeter/sessions")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", "attachment; filename=session_recordings.jsonl")

		encoder := json.NewEncoder(w)
		for _, recording := range sessions {
			if err := encoder.Encode(recording); err != nil {
				logrus.WithError(err).Error("Failed to encode session recording")
			}
		}
	})

	mux.HandleFunc("/api/sessions/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SessionID string `json:"session_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.SessionID == "" {
			http.Error(w, "session_id required", http.StatusBadRequest)
			return
		}
		if err := deleteSessionFromDisk("/var/cache/packetyeeter/sessions", req.SessionID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "message": "session deleted"})
	})

	mux.HandleFunc("/api/sessions/count", func(w http.ResponseWriter, r *http.Request) {
		sessions, err := loadSessionsFromDisk("/var/cache/packetyeeter/sessions")
		if err != nil {
			writeJSON(w, map[string]int{"count": 0})
			return
		}
		writeJSON(w, map[string]int{"count": len(sessions)})
	})

	// Active recordings endpoint
	mux.HandleFunc("/api/sessions/active", func(w http.ResponseWriter, r *http.Request) {
		if a.AIEngine == nil {
			writeJSON(w, []interface{}{})
			return
		}
		activeRecordings := a.AIEngine.GetActiveRecordings()
		writeJSON(w, activeRecordings)
	})

	mux.HandleFunc("/api/feedback/allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			// Delete from allowlist
			var req struct {
				IP string `json:"ip"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if req.IP == "" {
				http.Error(w, "ip required", http.StatusBadRequest)
				return
			}
			a.AIEngine.RemoveFromAllowlist(req.IP)
			writeJSON(w, map[string]string{"status": "ok", "message": "removed from allowlist"})
			return
		}
		// GET - return allowlist
		allowlist := a.AIEngine.GetAllowlist()
		writeJSON(w, allowlist)
	})

	// Bulk delete from allowlist
	mux.HandleFunc("/api/feedback/allowlist/bulk-delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IPs []string `json:"ips"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.IPs) == 0 {
			http.Error(w, "ips array required", http.StatusBadRequest)
			return
		}
		for _, ip := range req.IPs {
			a.AIEngine.RemoveFromAllowlist(ip)
		}
		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"message": fmt.Sprintf("removed %d IPs from allowlist", len(req.IPs)),
			"count":   len(req.IPs),
		})
	})

	// Clear all learning window labels
	mux.HandleFunc("/api/feedback/learning/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		count := a.AIEngine.ClearLearningWindow()
		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"message": fmt.Sprintf("cleared %d learning labels", count),
			"count":   count,
		})
	})

	// Bulk delete from learning window
	mux.HandleFunc("/api/feedback/learning/bulk-delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IPs []string `json:"ips"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.IPs) == 0 {
			http.Error(w, "ips array required", http.StatusBadRequest)
			return
		}
		count := a.AIEngine.BulkRemoveFromLearningWindow(req.IPs)
		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"message": fmt.Sprintf("removed %d IPs from learning window", count),
			"count":   count,
		})
	})

	// Manual recording start
	mux.HandleFunc("/api/sessions/record", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP    string `json:"ip"`
			Label string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.IP == "" {
			http.Error(w, "ip required", http.StatusBadRequest)
			return
		}
		// Use "manual" as default label if not provided
		if req.Label == "" {
			req.Label = "manual"
		}
		// Start recording immediately
		a.AIEngine.StartRecordingForIP(req.IP, req.Label)
		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"message": "started recording for " + req.IP,
			"ip":      req.IP,
			"label":   req.Label,
		})
	})

	// Submit manual label
	mux.HandleFunc("/api/labels/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP              string         `json:"ip"`
			ASN             string         `json:"asn,omitempty"`
			Org             string         `json:"org,omitempty"`
			JA4             string         `json:"ja4,omitempty"`
			JA4H            string         `json:"ja4h,omitempty"`
			Timestamp       string         `json:"timestamp,omitempty"`
			SignalCount     int            `json:"signal_count"`
			Confidence      float64        `json:"confidence"`
			MLConfidence    float64        `json:"ml_confidence"`
			AutoCategory    string         `json:"auto_category,omitempty"`
			SignalBreakdown map[string]int `json:"signal_breakdown,omitempty"`
			SourceBreakdown map[string]int `json:"source_breakdown,omitempty"`
			Label           string         `json:"label"`
			BotType         string         `json:"bot_type,omitempty"`
			Notes           string         `json:"notes,omitempty"`
			LabelConfidence int            `json:"label_confidence"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.IP == "" || req.Label == "" {
			http.Error(w, "ip and label required", http.StatusBadRequest)
			return
		}

		ipAddr := net.ParseIP(req.IP)
		if ipAddr == nil {
			http.Error(w, "invalid ip address", http.StatusBadRequest)
			return
		}

		// Get detection details
		det := a.AIEngine.GetLatestDetection("ip:" + req.IP)
		if det == nil {
			// Detection not found, but still save the label
			logrus.WithField("ip", req.IP).Warn("Detection not found, saving label without detection context")
		}

		// Save to training dataset (non-blocking)
		go func() {
			labels := []string{req.BotType}
			if det != nil {
				if err := saveLabeledDetection(det, req.Label, labels, req.Notes); err != nil {
					logrus.WithError(err).Error("Failed to save labeled detection")
				}
			}
		}()

		// Learn traffic patterns (non-blocking)
		go func() {
			if det != nil {
				// Extract user agent from signals
				userAgent := ""
				for _, sig := range det.Signals {
					if sig.Type == aidetection.SignalBotUA || sig.Type == aidetection.SignalNoCookies {
						if ua, ok := sig.Metadata["user_agent"].(string); ok && ua != "" {
							userAgent = ua
							break
						}
					}
				}
				if userAgent == "" && det.UserAgent != "" {
					userAgent = det.UserAgent
				}

				// Determine label for pattern learning
				patternLabel := "malicious"
				if req.Label == "human" || req.Label == "bot_legitimate" {
					patternLabel = "legitimate"
				}

				// Extract behavioral metrics from detection
				pathDiversity := 0.0
				requestRate := 0.0
				hasPathPattern := false
				hasTCPPattern := false
				hasUDPPattern := false
				signalTypes := make([]string, 0)

				// Count unique paths
				uniquePaths := make(map[string]bool)
				for _, sig := range det.Signals {
					if path, ok := sig.Metadata["path"].(string); ok && path != "" {
						uniquePaths[path] = true
					}
					signalTypes = append(signalTypes, string(sig.Type))

					// Check for TCP/UDP patterns
					switch sig.Type {
					case aidetection.SignalPortScanning, aidetection.SignalSYNFlood, aidetection.SignalIncompleteHandshake:
						hasTCPPattern = true
					case aidetection.SignalUDPFlood, aidetection.SignalICMPFlood:
						hasUDPPattern = true
					}
				}
				pathDiversity = float64(len(uniquePaths))

				// Calculate request rate (signals per second)
				if len(det.Signals) > 1 {
					timeSpan := det.DetectionTime.Sub(det.Signals[0].Timestamp).Seconds()
					if timeSpan > 0 {
						requestRate = float64(len(det.Signals)) / timeSpan
					}
				}

				// Detect path crawling pattern (sequential paths like /1, /2, /3 or /a, /b, /c)
				if pathDiversity >= 3 && requestRate > 0.5 {
					hasPathPattern = true
				}

				// Learn this pattern with behavioral signatures
				a.AIEngine.LearnPatternWithBehavior(userAgent, req.ASN, req.JA4H, patternLabel, true, req.Notes,
					pathDiversity, requestRate, hasPathPattern, hasTCPPattern, hasUDPPattern, signalTypes)

				logrus.WithFields(logrus.Fields{
					"ip":               req.IP,
					"user_agent":       userAgent,
					"asn":              req.ASN,
					"ja4h":             req.JA4H,
					"label":            patternLabel,
					"path_diversity":   pathDiversity,
					"request_rate":     requestRate,
					"has_path_pattern": hasPathPattern,
					"has_tcp_pattern":  hasTCPPattern,
					"has_udp_pattern":  hasUDPPattern,
				}).Info("Learned traffic pattern with behavioral signatures from manual label")
			}
		}()

		// Start learning window and train model (non-blocking to avoid deadlock)
		go func() {
			if req.Label == "human" || req.Label == "bot_legitimate" {
				// Record false positive to trigger learning window and ML training
				a.AIEngine.RecordFalsePositive(ipAddr, req.ASN, req.Confidence, aidetection.BotCategory(req.AutoCategory), true)

				logrus.WithFields(logrus.Fields{
					"ip":    req.IP,
					"label": req.Label,
				}).Info("Started learning window for legitimate traffic")
			} else if req.Label == "bot" {
				// Record true positive to reinforce ML
				a.AIEngine.RecordTruePositive(ipAddr, req.ASN, req.Confidence, aidetection.BotCategory(req.AutoCategory), true)

				logrus.WithFields(logrus.Fields{
					"ip":    req.IP,
					"label": req.Label,
				}).Info("Started learning window for malicious traffic")
			}
		}()

		// Return immediately to avoid blocking the UI
		writeJSON(w, map[string]interface{}{
			"status":             "ok",
			"message":            "Label submission in progress",
			"added_to_allowlist": req.Label == "human" || req.Label == "bot_legitimate",
		})
	})

	// Get learned patterns
	mux.HandleFunc("/api/patterns", func(w http.ResponseWriter, r *http.Request) {
		patterns := a.AIEngine.GetLearnedPatterns()
		writeJSON(w, patterns)
	})

	// Delete a learned pattern
	mux.HandleFunc("/api/patterns/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Key == "" {
			http.Error(w, "pattern key required", http.StatusBadRequest)
			return
		}
		a.AIEngine.RemovePattern(req.Key)
		writeJSON(w, map[string]string{"status": "ok"})
	})

	// Export labeled dataset
	mux.HandleFunc("/api/labels/export", func(w http.ResponseWriter, r *http.Request) {
		dataFile := filepath.Join("/var/lib/packetyeeter", "labeled_dataset.jsonl")
		data, err := os.ReadFile(dataFile)
		if err != nil {
			if os.IsNotExist(err) {
				writeJSON(w, []interface{}{})
				return
			}
			http.Error(w, "failed to read dataset", http.StatusInternalServerError)
			return
		}

		// Parse JSONL and return as array
		lines := strings.Split(string(data), "\n")
		var samples []map[string]interface{}
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var sample map[string]interface{}
			if err := json.Unmarshal([]byte(line), &sample); err != nil {
				logrus.WithError(err).Warn("Failed to parse labeled sample")
				continue
			}
			samples = append(samples, sample)
		}
		writeJSON(w, samples)
	})

	// Get unique IPs from labeled dataset
	mux.HandleFunc("/api/labels/ips", func(w http.ResponseWriter, r *http.Request) {
		dataFile := filepath.Join("/var/lib/packetyeeter", "labeled_dataset.jsonl")
		data, err := os.ReadFile(dataFile)
		if err != nil {
			if os.IsNotExist(err) {
				writeJSON(w, []string{})
				return
			}
			http.Error(w, "failed to read dataset", http.StatusInternalServerError)
			return
		}

		// Parse JSONL and extract unique IPs
		ipSet := make(map[string]bool)
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var sample map[string]interface{}
			if err := json.Unmarshal([]byte(line), &sample); err != nil {
				continue
			}
			if ip, ok := sample["ip"].(string); ok && ip != "" {
				ipSet[ip] = true
			}
		}

		// Convert set to slice
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}

		writeJSON(w, ips)
	})

	// Delete specific labeled sample
	mux.HandleFunc("/api/labels/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP        string `json:"ip"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.IP == "" || req.Timestamp == "" {
			http.Error(w, "ip and timestamp required", http.StatusBadRequest)
			return
		}

		dataFile := filepath.Join("/var/lib/packetyeeter", "labeled_dataset.jsonl")
		data, err := os.ReadFile(dataFile)
		if err != nil {
			http.Error(w, "failed to read dataset", http.StatusInternalServerError)
			return
		}

		// Filter out the line to delete
		lines := strings.Split(string(data), "\n")
		var newLines []string
		deleted := false
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var sample map[string]interface{}
			if err := json.Unmarshal([]byte(line), &sample); err != nil {
				newLines = append(newLines, line)
				continue
			}
			// Skip the line to delete
			if sample["ip"] == req.IP && sample["timestamp"] == req.Timestamp {
				deleted = true
				continue
			}
			newLines = append(newLines, line)
		}

		if !deleted {
			http.Error(w, "label not found", http.StatusNotFound)
			return
		}

		// Write back
		newData := strings.Join(newLines, "\n")
		if len(newLines) > 0 {
			newData += "\n"
		}
		if err := os.WriteFile(dataFile, []byte(newData), 0644); err != nil {
			http.Error(w, "failed to save dataset", http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]string{"status": "ok", "message": "label deleted"})
	})

	// Traffic analytics endpoint
	mux.HandleFunc("/api/analytics/traffic", func(w http.ResponseWriter, r *http.Request) {
		history := a.AIEngine.GetDetectionHistory(6 * time.Hour)

		// Aggregate data
		hostnames := make(map[string]int)
		paths := make(map[string]int)
		methods := make(map[string]int)
		userAgents := make(map[string]int)
		asns := make(map[string]int)
		// countryKey -> {code, name, count}
		type countryAgg struct {
			Code  string
			Name  string
			Count int
		}
		countries := make(map[string]*countryAgg)
		blockCandidateCountries := make(map[string]*countryAgg)
		suspiciousCountries := make(map[string]*countryAgg)
		addCountry := func(dst map[string]*countryAgg, det *aidetection.DetectionEvent) {
			if det.CountryCode == "" || det.CountryCode == "unknown" {
				return
			}
			agg, ok := dst[det.CountryCode]
			if !ok {
				agg = &countryAgg{Code: det.CountryCode, Name: det.Country}
				dst[det.CountryCode] = agg
			}
			agg.Count++
		}
		isSuspiciousCategory := func(category aidetection.BotCategory) bool {
			switch category {
			case aidetection.BotCategoryMalicious,
				aidetection.BotCategoryScanner,
				aidetection.BotCategoryDDoS,
				aidetection.BotCategoryScraper,
				aidetection.BotCategoryScript,
				aidetection.BotCategoryAICrawlerUnknown,
				aidetection.BotCategorySearchUnknown:
				return true
			default:
				return false
			}
		}

		for _, det := range history {
			if det.Hostname != "" {
				hostnames[det.Hostname]++
			}
			if det.Path != "" {
				paths[det.Path]++
			}
			if det.Method != "" {
				methods[det.Method]++
			}
			if det.UserAgent != "" {
				// Truncate long user agents for display
				ua := det.UserAgent
				if len(ua) > 100 {
					ua = ua[:97] + "..."
				}
				userAgents[ua]++
			}
			if det.ASN != "" {
				asns[det.ASN]++
			}
			addCountry(countries, det)
			if det.WouldBlock {
				addCountry(blockCandidateCountries, det)
			}
			if isSuspiciousCategory(det.BotCategory) {
				addCountry(suspiciousCountries, det)
			}
		}

		// Convert to sorted slices
		type countItem struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}

		topHosts := make([]countItem, 0, len(hostnames))
		for k, v := range hostnames {
			topHosts = append(topHosts, countItem{Name: k, Count: v})
		}
		sort.Slice(topHosts, func(i, j int) bool {
			return topHosts[i].Count > topHosts[j].Count
		})
		if len(topHosts) > 20 {
			topHosts = topHosts[:20]
		}

		topPaths := make([]countItem, 0, len(paths))
		for k, v := range paths {
			topPaths = append(topPaths, countItem{Name: k, Count: v})
		}
		sort.Slice(topPaths, func(i, j int) bool {
			return topPaths[i].Count > topPaths[j].Count
		})
		if len(topPaths) > 20 {
			topPaths = topPaths[:20]
		}

		topMethods := make([]countItem, 0, len(methods))
		for k, v := range methods {
			topMethods = append(topMethods, countItem{Name: k, Count: v})
		}
		sort.Slice(topMethods, func(i, j int) bool {
			return topMethods[i].Count > topMethods[j].Count
		})

		topUAs := make([]countItem, 0, len(userAgents))
		for k, v := range userAgents {
			topUAs = append(topUAs, countItem{Name: k, Count: v})
		}
		sort.Slice(topUAs, func(i, j int) bool {
			return topUAs[i].Count > topUAs[j].Count
		})
		if len(topUAs) > 20 {
			topUAs = topUAs[:20]
		}

		topASNs := make([]countItem, 0, len(asns))
		for k, v := range asns {
			topASNs = append(topASNs, countItem{Name: k, Count: v})
		}
		sort.Slice(topASNs, func(i, j int) bool {
			return topASNs[i].Count > topASNs[j].Count
		})
		if len(topASNs) > 20 {
			topASNs = topASNs[:20]
		}

		type countryItem struct {
			Code  string `json:"code"`
			Name  string `json:"name"`
			Count int    `json:"count"`
		}
		topCountryItems := func(src map[string]*countryAgg) []countryItem {
			items := make([]countryItem, 0, len(src))
			for _, agg := range src {
				items = append(items, countryItem{Code: agg.Code, Name: agg.Name, Count: agg.Count})
			}
			sort.Slice(items, func(i, j int) bool {
				return items[i].Count > items[j].Count
			})
			if len(items) > 20 {
				items = items[:20]
			}
			return items
		}
		topCountries := topCountryItems(countries)

		writeJSON(w, map[string]interface{}{
			"hostnames":                  topHosts,
			"paths":                      topPaths,
			"methods":                    topMethods,
			"user_agents":                topUAs,
			"asns":                       topASNs,
			"countries":                  topCountries,
			"countries_block_candidates": topCountryItems(blockCandidateCountries),
			"countries_suspicious":       topCountryItems(suspiciousCountries),
			"total_requests":             len(history),
		})
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// saveLabeledDetection appends a labeled detection to the training dataset
func saveLabeledDetection(det *aidetection.DetectionEvent, label string, labels []string, reason string) error {
	dataDir := "/var/lib/packetyeeter"
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return err
	}

	dataFile := filepath.Join(dataDir, "labeled_dataset.jsonl")
	f, err := os.OpenFile(dataFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Create training sample
	sample := map[string]interface{}{
		"ip":               det.IP.String(),
		"asn":              det.ASN,
		"org":              det.Org,
		"user_agent":       det.UserAgent,
		"ja4":              det.JA4,
		"ja4h":             det.JA4H,
		"signal_count":     det.SignalCount,
		"confidence":       det.Confidence,
		"ml_confidence":    det.MLConfidence,
		"bot_category":     det.BotCategory,
		"signal_breakdown": det.SignalBreakdown,
		"source_breakdown": det.SourceBreakdown,
		"label":            label,
		"labels":           labels,
		"reason":           reason,
		"timestamp":        time.Now().Format(time.RFC3339),
	}

	data, err := json.Marshal(sample)
	if err != nil {
		return err
	}

	_, err = f.Write(append(data, '\n'))
	return err
}

type detectionDTO struct {
	IP                 string                           `json:"ip,omitempty"`
	DestIP             string                           `json:"dest_ip,omitempty"`
	DstPort            uint32                           `json:"dst_port,omitempty"`
	Hostname           string                           `json:"hostname,omitempty"`
	Method             string                           `json:"method,omitempty"`
	Path               string                           `json:"path,omitempty"`
	JA4                string                           `json:"ja4,omitempty"`
	JA4H               string                           `json:"ja4h,omitempty"`
	JA4T               string                           `json:"ja4t,omitempty"`
	ASN                string                           `json:"asn,omitempty"`
	Org                string                           `json:"org,omitempty"`
	Country            string                           `json:"country,omitempty"`
	CountryCode        string                           `json:"country_code,omitempty"`
	UserAgent          string                           `json:"user_agent,omitempty"`
	SignalCount        int                              `json:"signal_count"`
	DetectionTime      string                           `json:"detection_time"`
	EWMABaseline       float64                          `json:"ewma_baseline"`
	Confidence         float64                          `json:"confidence"`
	Score              float64                          `json:"score"`
	MLConfidence       float64                          `json:"ml_confidence"`
	RuleConfidence     float64                          `json:"rule_confidence"`
	MLCategory         aidetection.BotCategory          `json:"ml_category"`
	MLModelTier        string                           `json:"ml_model_tier"`
	BotCategory        aidetection.BotCategory          `json:"bot_category"`
	VerificationStatus aidetection.VerificationStatus   `json:"verification_status"`
	BlockReason        string                           `json:"block_reason"`
	WouldBlock         bool                             `json:"would_block"`
	SignalBreakdown    map[aidetection.SignalType]int   `json:"signal_breakdown"`
	SourceBreakdown    map[aidetection.SignalSource]int `json:"source_breakdown"`
	Signals            []signalDTO                      `json:"signals"`
	Reasons            []string                         `json:"reasons,omitempty"`
	Metadata           map[string]interface{}           `json:"metadata,omitempty"`
}

type signalDTO struct {
	Type      aidetection.SignalType   `json:"type"`
	Source    aidetection.SignalSource `json:"source"`
	Weight    float64                  `json:"weight"`
	Timestamp string                   `json:"timestamp"`
	Metadata  map[string]interface{}   `json:"metadata,omitempty"`
}

func formatDetection(det *aidetection.DetectionEvent) detectionDTO {
	ip := ""
	if det.IP != nil {
		ip = det.IP.String()
	}
	dto := detectionDTO{
		IP:                 ip,
		DestIP:             det.DestIP,
		DstPort:            det.DstPort,
		Hostname:           det.Hostname,
		Method:             det.Method,
		Path:               det.Path,
		JA4:                det.JA4,
		JA4H:               det.JA4H,
		JA4T:               det.JA4T,
		ASN:                det.ASN,
		Org:                det.Org,
		Country:            det.Country,
		CountryCode:        det.CountryCode,
		UserAgent:          det.UserAgent,
		SignalCount:        det.SignalCount,
		DetectionTime:      det.DetectionTime.Format(time.RFC3339),
		EWMABaseline:       det.EWMABaseline,
		Confidence:         det.Confidence,
		Score:              det.Score,
		MLConfidence:       det.MLConfidence,
		RuleConfidence:     det.RuleConfidence,
		MLCategory:         det.MLCategory,
		MLModelTier:        det.MLModelTier,
		BotCategory:        det.BotCategory,
		VerificationStatus: det.VerificationStatus,
		BlockReason:        det.BlockReason,
		WouldBlock:         det.WouldBlock,
		SignalBreakdown:    det.SignalBreakdown,
		SourceBreakdown:    det.SourceBreakdown,
		Reasons:            det.Reasons,
		Metadata:           det.Metadata,
	}
	for _, sig := range det.Signals {
		dto.Signals = append(dto.Signals, signalDTO{
			Type:      sig.Type,
			Source:    sig.Source,
			Weight:    sig.Weight,
			Timestamp: sig.Timestamp.Format(time.RFC3339),
			Metadata:  sig.Metadata,
		})
	}
	return dto
}

func formatDetections(dets []*aidetection.DetectionEvent) []detectionDTO {
	out := make([]detectionDTO, 0, len(dets))
	for _, det := range dets {
		out = append(out, formatDetection(det))
	}
	return out
}
