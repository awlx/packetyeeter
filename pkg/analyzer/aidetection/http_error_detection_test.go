package aidetection

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestEvaluateWindowSingleTypeHTTPErrorDetects(t *testing.T) {
	e := New(Config{
		Workers:             1,
		BufferSize:          100,
		WarmupPeriod:        time.Nanosecond,
		StaticThreshold:     3,
		ConfidenceThreshold: 0.8,
	})
	ch := make(chan DetectionEvent, 1)
	e.RegisterDetectionHandler(testHandler{ch})
	time.Sleep(5 * time.Millisecond)

	ip := net.ParseIP("198.51.100.50")
	key := "ip:" + ip.String()
	now := time.Now()
	signals := make([]Signal, 0, 3)
	for i := 0; i < 3; i++ {
		signals = append(signals, Signal{
			IP:        ip,
			Type:      SignalErrorBurst,
			Source:    SourceSPOE,
			Weight:    8.0,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Metadata: map[string]interface{}{
				"host":        "doh.example.net",
				"path":        "/dns-query",
				"status_code": uint32(400),
				"4xx_count":   20,
			},
		})
	}

	e.evaluateWindow(map[string][]Signal{key: signals})

	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected detection for pure high-severity error_burst flood (single signal type)")
	}
}

func TestCampaignHTTPErrorSourceBreadth(t *testing.T) {
	cfg := testCampaignConfig()
	// Match production-style weak-signal gate so high-weight error_burst fails
	// weak_source_breadth and must use the HTTP-error path.
	cfg.WeakSignalMaxWeight = 2.0
	cfg.WeakSourceMaxWeight = 5.0
	cfg.MinWeakSourceIPs = 4
	cfg.MinSignals = 4
	agg := NewCampaignAggregator(cfg)
	now := time.Date(2026, 8, 10, 6, 0, 0, 0, time.UTC)

	for i := 1; i <= 6; i++ {
		agg.Record(Signal{
			Type:      SignalErrorBurst,
			Source:    SourceSPOE,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i)),
			Weight:    10.0, // well above WeakSignalMaxWeight
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Metadata: map[string]interface{}{
				"dest_ip":      "203.0.113.10",
				"dst_port":     uint32(443),
				"collector_id": "collector-a",
				"host":         "doh.example.net",
				"path":         "/dns-query",
				"status_code":  uint32(400),
			},
		})
	}

	detections := agg.Evaluate(now.Add(10 * time.Second))
	if len(detections) == 0 {
		t.Fatal("expected HTTP error source-breadth campaign for high-weight error_burst flood")
	}
	found := false
	for _, d := range detections {
		if d.Reason == "http_error_source_breadth" && d.Vector == SignalErrorBurst {
			found = true
			if d.SourceIPs < 4 {
				t.Fatalf("source IPs = %d, want >= 4", d.SourceIPs)
			}
		}
	}
	if !found {
		t.Fatalf("expected http_error_source_breadth detection, got %#v", detections)
	}
}

func TestIsHTTPClientErrorVector(t *testing.T) {
	if !isHTTPClientErrorVector(SignalErrorBurst) || !isHTTPClientErrorVector(SignalExcessiveClientError) {
		t.Fatal("expected HTTP client error vectors")
	}
	if isHTTPClientErrorVector(SignalMissingSecCH) {
		t.Fatal("missing_sec_ch is not an HTTP client error vector")
	}
}
