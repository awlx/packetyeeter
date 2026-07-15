package aidetection

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"PacketYeeter/pkg/utils/ewma"
)

func TestHighCardinalityStateRemainsBounded(t *testing.T) {
	engine := New(Config{Workers: 1, BufferSize: 10})
	engine.metricsMaxEntities = 100
	engine.profilesMaxSize = 100
	engine.historyManager.maxHistories = 100
	engine.campaigns.cfg.MaxCampaigns = 100

	window := make(map[string][]Signal)
	for i := 0; i < 1000; i++ {
		engine.processSignal(Signal{
			Type:      SignalTCPMetadata,
			Source:    SourceTCP,
			IP:        net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1)),
			Timestamp: time.Now(),
		}, window)
	}

	if got := len(engine.metricsLastSeen); got > engine.metricsMaxEntities {
		t.Fatalf("metric entities grew to %d, max %d", got, engine.metricsMaxEntities)
	}
	if got := len(engine.behavioralProfiles); got > engine.profilesMaxSize {
		t.Fatalf("behavioral profiles grew to %d, max %d", got, engine.profilesMaxSize)
	}
	if got := engine.historyManager.Count(); got > engine.historyManager.maxHistories {
		t.Fatalf("event histories grew to %d, max %d", got, engine.historyManager.maxHistories)
	}
	if got := len(engine.campaigns.campaigns); got > engine.campaigns.cfg.MaxCampaigns {
		t.Fatalf("campaigns grew to %d, max %d", got, engine.campaigns.cfg.MaxCampaigns)
	}
}

func TestDetectionSnapshotsAreCompactAndCoherentlyEvicted(t *testing.T) {
	engine := New(Config{Workers: 1, BufferSize: 10})
	engine.latestMaxEvents = 1
	engine.historyMaxSize = 2

	largeValue := strings.Repeat("x", 64*1024)
	signals := make([]Signal, 1000)
	for i := range signals {
		signals[i] = Signal{
			Type:      SignalTCPMetadata,
			Source:    SourceTCP,
			IP:        net.ParseIP("2001:db8::1"),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"path":         fmt.Sprintf("/%d", i),
				"large_unused": largeValue,
			},
		}
	}
	first := &DetectionEvent{
		IP:              net.ParseIP("2001:db8::1"),
		ASN:             "AS64500",
		JA4H:            "first",
		Signals:         signals,
		SignalCount:     len(signals),
		DetectionTime:   time.Now().Add(-time.Second),
		SignalBreakdown: map[SignalType]int{SignalTCPMetadata: len(signals)},
		SourceBreakdown: map[SignalSource]int{SourceTCP: len(signals)},
		FeedbackFeatures: &MLFeatures{
			SignalCount: 1000,
			SignalRate:  123.5,
			EventHistory: &EventHistorySnapshot{
				Events:     make([]SignalEvent, 100),
				Timestamps: make([]time.Time, 100),
			},
		},
	}
	engine.cacheDetection(first, detectionEntityKeys(first, ""))
	engine.addDetectionHistory(first)

	if len(first.Signals) != 1000 {
		t.Fatalf("live detection was mutated before handlers: got %d signals", len(first.Signals))
	}
	cached := engine.GetLatestDetection("ip:2001:db8::1")
	if cached == nil {
		t.Fatal("expected cached detection")
	}
	if got := len(cached.Signals); got != retainedDetectionSignals {
		t.Fatalf("cached %d signals, want %d", got, retainedDetectionSignals)
	}
	if _, retained := cached.Signals[0].Metadata["large_unused"]; retained {
		t.Fatal("compact snapshot retained unused large metadata")
	}
	if cached.FeedbackFeatures == nil || cached.FeedbackFeatures.SignalCount != 1000 || cached.FeedbackFeatures.SignalRate != 123.5 {
		t.Fatal("compact snapshot lost aggregate feedback-training features")
	}
	if got := len(cached.FeedbackFeatures.EventHistory.Events); got != retainedDetectionSignals {
		t.Fatalf("feedback history retained %d events, want %d", got, retainedDetectionSignals)
	}

	second := *first
	second.IP = net.ParseIP("2001:db8::2")
	second.ASN = "AS64501"
	second.JA4H = "second"
	second.DetectionTime = time.Now()
	engine.cacheDetection(&second, detectionEntityKeys(&second, ""))

	if engine.GetLatestDetection("ja4h:first") != nil {
		t.Fatal("evicting an event left a dangling secondary cache key")
	}
	if got := len(engine.latestDetectionKeys); got != 1 {
		t.Fatalf("latest cache retained %d unique events, want 1", got)
	}
}

func TestDetectionHistoryAndCampaignEventsRemainBounded(t *testing.T) {
	engine := New(Config{Workers: 1, BufferSize: 10})
	engine.historyMaxSize = 3
	for i := 0; i < 20; i++ {
		engine.addDetectionHistory(&DetectionEvent{
			IP:            net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1)),
			DetectionTime: time.Now().Add(time.Duration(i) * time.Millisecond),
			Signals:       make([]Signal, 100),
		})
	}
	if got := len(engine.detectionHistory); got != engine.historyMaxSize {
		t.Fatalf("history retained %d events, want %d", got, engine.historyMaxSize)
	}
	for _, event := range engine.detectionHistory {
		if len(event.Signals) > retainedDetectionSignals {
			t.Fatalf("history snapshot retained %d signals", len(event.Signals))
		}
	}

	aggregator := NewCampaignAggregator(CampaignConfig{
		Window:       time.Minute,
		Retention:    2 * time.Minute,
		MaxCampaigns: 8,
		MaxEvents:    10,
	})
	now := time.Now()
	for i := 0; i < 100; i++ {
		aggregator.Record(Signal{
			Type:      SignalUDPFlood,
			Source:    SourceUDP,
			IP:        net.ParseIP(fmt.Sprintf("198.51.100.%d", i%250+1)),
			Timestamp: now,
			Metadata: map[string]interface{}{
				"dest_ip":      fmt.Sprintf("203.0.%d.%d", i/250, i%250+1),
				"collector_id": fmt.Sprintf("collector-%d", i),
				"large_unused": strings.Repeat("y", 4096),
			},
		})
	}
	if got := len(aggregator.campaigns); got > aggregator.cfg.MaxCampaigns {
		t.Fatalf("campaign map retained %d entries, max %d", got, aggregator.cfg.MaxCampaigns)
	}
	for _, campaign := range aggregator.campaigns {
		if len(campaign.events) > aggregator.cfg.MaxEvents {
			t.Fatalf("campaign retained %d events, max %d", len(campaign.events), aggregator.cfg.MaxEvents)
		}
	}
}

func TestCleanupRetainedStateExpiresAllEntityIndexes(t *testing.T) {
	engine := New(Config{Workers: 1, BufferSize: 10})
	old := time.Now().Add(-time.Hour)
	engine.metricsTTL = time.Minute
	engine.profilesTTL = time.Minute
	engine.latestTTL = time.Minute

	engine.metricsLastSeen["ip:192.0.2.1"] = old
	engine.signalsByIP["192.0.2.1"] = 1
	engine.signalTypesByIP["192.0.2.1"] = map[string]uint64{"x": 1}
	engine.behavioralProfiles["ip:192.0.2.1"] = &BehavioralProfile{LastSeen: old}
	engine.ewmaMap["ip:192.0.2.1"] = &ewma.State{LastTime: old}
	engine.logThrottle["ip:192.0.2.1"] = old
	engine.preDetectionBuffers["192.0.2.1"] = nil
	engine.preDetectionLastSeen["192.0.2.1"] = old
	engine.cacheDetection(&DetectionEvent{
		IP:            net.ParseIP("192.0.2.1"),
		DetectionTime: old,
	}, []string{"ip:192.0.2.1"})

	engine.cleanupRetainedState(time.Now())

	if len(engine.metricsLastSeen) != 0 || len(engine.signalsByIP) != 0 || len(engine.signalTypesByIP) != 0 {
		t.Fatal("metric indexes retained expired entity state")
	}

	if len(engine.behavioralProfiles) != 0 || len(engine.logThrottle) != 0 || len(engine.preDetectionBuffers) != 0 {
		t.Fatal("auxiliary maps retained expired entity state")
	}
	if len(engine.latestDetections) != 0 || len(engine.latestDetectionKeys) != 0 {
		t.Fatal("latest detection cache retained expired references")
	}
}

func TestDetectionMetricsRespectEntityAdmissionCap(t *testing.T) {
	engine := New(Config{Workers: 1, BufferSize: 10})
	engine.metricsMaxEntities = 2
	engine.metricsLastSeen["ip:192.0.2.1"] = time.Now()
	engine.metricsLastSeen["ip:192.0.2.2"] = time.Now()

	engine.metricsMu.Lock()
	admitted := engine.admitMetricEntityLocked(
		"ip:192.0.2.3",
		engine.detectionsByIP,
		"192.0.2.3",
		time.Now(),
	)
	if admitted {
		engine.detectionsByIP["192.0.2.3"]++
	}
	engine.metricsMu.Unlock()

	if admitted || len(engine.detectionsByIP) != 0 {
		t.Fatal("detection metrics admitted an unindexed entity past the cap")
	}

	engine.metricsMu.Lock()
	admitted = engine.admitMetricEntityLocked(
		"ip:192.0.2.1",
		engine.detectionsByIP,
		"192.0.2.1",
		time.Now(),
	)
	engine.metricsMu.Unlock()
	if !admitted {
		t.Fatal("existing indexed entity lost its first detection metric at capacity")
	}
}

func TestLoadPatternsKeepsBoundedPrioritySet(t *testing.T) {
	now := time.Now()
	patterns := []LearnedPattern{
		{Key: "auto-old", LastSeen: now.Add(-2 * time.Hour)},
		{Key: "auto-newest", LastSeen: now},
		{Key: "user", LastSeen: now.Add(-24 * time.Hour), LabeledByUser: true},
		{Key: "auto-newer", LastSeen: now.Add(-time.Hour)},
	}
	data, err := json.Marshal(patterns)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "patterns.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	feedback := &FeedbackLoop{
		learnedPatterns: make(map[string]LearnedPattern),
		patternsPath:    path,
		maxPatterns:     3,
	}
	feedback.loadPatterns()

	if got := len(feedback.learnedPatterns); got != feedback.maxPatterns {
		t.Fatalf("loaded %d patterns, want %d", got, feedback.maxPatterns)
	}
	for _, key := range []string{"user", "auto-newest", "auto-newer"} {
		if _, ok := feedback.learnedPatterns[key]; !ok {
			t.Errorf("priority pattern %q was not loaded", key)
		}
	}
	if _, ok := feedback.learnedPatterns["auto-old"]; ok {
		t.Error("older automatic pattern was loaded past the cap")
	}
}
