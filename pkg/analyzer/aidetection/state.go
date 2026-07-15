package aidetection

import (
	"net"
	"strings"
	"time"

	"PacketYeeter/pkg/metrics"
)

const retainedDetectionSignals = 16

func detectionEntityKeys(event *DetectionEvent, extra string) []string {
	keys := make([]string, 0, 4)
	if event != nil {
		if event.IP != nil {
			keys = append(keys, "ip:"+event.IP.String())
		}
		if event.ASN != "" {
			keys = append(keys, "asn:"+event.ASN)
		}
		if event.JA4H != "" {
			keys = append(keys, "ja4h:"+event.JA4H)
		}
	}
	if extra != "" {
		keys = append(keys, extra)
	}
	return keys
}

func compactDetection(event *DetectionEvent) *DetectionEvent {
	if event == nil {
		return nil
	}
	compact := *event
	if compact.DetectionTime.IsZero() {
		compact.DetectionTime = time.Now()
	}
	if event.IP != nil {
		compact.IP = append(net.IP(nil), event.IP...)
	}
	if len(event.Signals) > retainedDetectionSignals {
		compact.Signals = make([]Signal, retainedDetectionSignals)
		step := float64(len(event.Signals)) / float64(retainedDetectionSignals)
		for i := range compact.Signals {
			compact.Signals[i] = compactSignal(event.Signals[int(float64(i)*step)])
		}
	} else {
		compact.Signals = make([]Signal, len(event.Signals))
		for i := range event.Signals {
			compact.Signals[i] = compactSignal(event.Signals[i])
		}
	}
	compact.SignalBreakdown = cloneSignalBreakdown(event.SignalBreakdown)
	compact.SourceBreakdown = cloneSourceBreakdown(event.SourceBreakdown)
	compact.Reasons = append([]string(nil), event.Reasons...)
	compact.Metadata = cloneMetadata(event.Metadata, nil)
	compact.FeedbackFeatures = compactMLFeatures(event.FeedbackFeatures)
	return &compact
}

func compactMLFeatures(features *MLFeatures) *MLFeatures {
	if features == nil {
		return nil
	}
	compact := *features
	compact.ThreatTags = append([]string(nil), features.ThreatTags...)
	compact.SignalTypeVector = cloneSignalBreakdown(features.SignalTypeVector)
	compact.SourceVector = cloneSourceBreakdown(features.SourceVector)
	if features.EventHistory != nil {
		snapshot := features.EventHistory
		start := 0
		if len(snapshot.Events) > retainedDetectionSignals {
			start = len(snapshot.Events) - retainedDetectionSignals
		}
		history := EventHistorySnapshot{
			Events:      append([]SignalEvent(nil), snapshot.Events[start:]...),
			Paths:       tailStrings(snapshot.Paths, retainedDetectionSignals),
			UserAgents:  tailStrings(snapshot.UserAgents, retainedDetectionSignals),
			Methods:     tailStrings(snapshot.Methods, retainedDetectionSignals),
			Referers:    tailStrings(snapshot.Referers, retainedDetectionSignals),
			AcceptLangs: tailStrings(snapshot.AcceptLangs, retainedDetectionSignals),
			Timestamps:  tailTimes(snapshot.Timestamps, retainedDetectionSignals),
		}
		for i := range history.Events {
			history.Events[i].Metadata = cloneMetadata(history.Events[i].Metadata, nil)
		}
		compact.EventHistory = &history
	}
	return &compact
}

func tailStrings(values []string, max int) []string {
	if len(values) > max {
		values = values[len(values)-max:]
	}
	return append([]string(nil), values...)
}

func tailTimes(values []time.Time, max int) []time.Time {
	if len(values) > max {
		values = values[len(values)-max:]
	}
	return append([]time.Time(nil), values...)
}

func (e *Engine) feedbackFeatures(event *DetectionEvent) MLFeatures {
	if event.FeedbackFeatures != nil {
		return *compactMLFeatures(event.FeedbackFeatures)
	}
	return e.extractMLFeatures(
		event.Signals,
		event.SignalBreakdown,
		event.SourceBreakdown,
		nil,
		0,
	)
}

func compactSignal(signal Signal) Signal {
	compact := signal
	if signal.IP != nil {
		compact.IP = append(net.IP(nil), signal.IP...)
	}
	compact.Metadata = cloneMetadata(signal.Metadata, map[string]struct{}{
		"path": {}, "method": {}, "user_agent": {}, "referer": {},
		"accept_language": {}, "status_code": {}, "dest_ip": {}, "dst_port": {},
	})
	return compact
}

func cloneMetadata(src map[string]interface{}, allowed map[string]struct{}) map[string]interface{} {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]interface{}, len(src))
	for key, value := range src {
		if allowed != nil {
			if _, ok := allowed[key]; !ok {
				continue
			}
		}
		dst[key] = value
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func cloneSignalBreakdown(src map[SignalType]int) map[SignalType]int {
	dst := make(map[SignalType]int, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneSourceBreakdown(src map[SignalSource]int) map[SignalSource]int {
	dst := make(map[SignalSource]int, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func (e *Engine) cacheDetection(event *DetectionEvent, keys []string) {
	compact := compactDetection(event)
	if compact == nil || len(keys) == 0 {
		return
	}

	e.detectionsMu.Lock()
	defer e.detectionsMu.Unlock()
	if e.latestDetections == nil {
		e.latestDetections = make(map[string]*DetectionEvent)
	}
	if e.latestDetectionKeys == nil {
		e.latestDetectionKeys = make(map[*DetectionEvent]map[string]struct{})
	}
	if e.latestMaxEvents <= 0 {
		e.latestMaxEvents = 10000
	}
	if e.latestTTL <= 0 {
		e.latestTTL = 6 * time.Hour
	}

	for _, key := range keys {
		if old := e.latestDetections[key]; old != nil {
			delete(e.latestDetectionKeys[old], key)
			if len(e.latestDetectionKeys[old]) == 0 {
				delete(e.latestDetectionKeys, old)
			}
		}
		e.latestDetections[key] = compact
	}
	keySet := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		keySet[key] = struct{}{}
	}
	e.latestDetectionKeys[compact] = keySet
	e.pruneLatestDetectionsLocked(time.Now(), false)
}

func (e *Engine) pruneLatestDetectionsLocked(now time.Time, expire bool) {
	if expire {
		cutoff := now.Add(-e.latestTTL)
		for event, keys := range e.latestDetectionKeys {
			if event.DetectionTime.Before(cutoff) || event.DetectionTime.After(now.Add(5*time.Minute)) {
				e.removeDetectionLocked(event, keys)
			}
		}
	}
	for len(e.latestDetectionKeys) > e.latestMaxEvents {
		var oldest *DetectionEvent
		for event := range e.latestDetectionKeys {
			if oldest == nil || event.DetectionTime.Before(oldest.DetectionTime) {
				oldest = event
			}
		}
		if oldest == nil {
			break
		}
		e.removeDetectionLocked(oldest, e.latestDetectionKeys[oldest])
	}
}

func (e *Engine) removeDetectionLocked(event *DetectionEvent, keys map[string]struct{}) {
	for key := range keys {
		if e.latestDetections[key] == event {
			delete(e.latestDetections, key)
		}
	}
	delete(e.latestDetectionKeys, event)
}

func (e *Engine) addDetectionHistory(event *DetectionEvent) {
	compact := compactDetection(event)
	if compact == nil {
		return
	}
	e.historyMu.Lock()
	defer e.historyMu.Unlock()
	if e.historyMaxSize <= 0 {
		e.historyMaxSize = 5000
	}
	if e.historyMaxAge <= 0 {
		e.historyMaxAge = 6 * time.Hour
	}
	e.detectionHistory = append(e.detectionHistory, compact)
	e.pruneDetectionHistoryLocked(time.Now())
}

func (e *Engine) pruneDetectionHistoryLocked(now time.Time) {
	cutoff := now.Add(-e.historyMaxAge)
	first := 0
	for first < len(e.detectionHistory) && e.detectionHistory[first].DetectionTime.Before(cutoff) {
		first++
	}
	if first > 0 {
		copy(e.detectionHistory, e.detectionHistory[first:])
		e.detectionHistory = e.detectionHistory[:len(e.detectionHistory)-first]
	}
	if excess := len(e.detectionHistory) - e.historyMaxSize; excess > 0 {
		copy(e.detectionHistory, e.detectionHistory[excess:])
		e.detectionHistory = e.detectionHistory[:e.historyMaxSize]
	}
}

func (e *Engine) admitMetricEntityLocked(entityID string, counts map[string]uint64, key string, seen time.Time) bool {
	if seen.IsZero() {
		seen = time.Now()
	}
	_, admitted := e.metricsLastSeen[entityID]
	if _, exists := counts[key]; !exists && !admitted && len(e.metricsLastSeen) >= e.metricsMaxEntities {
		return false
	}
	e.metricsLastSeen[entityID] = seen
	return true
}

func (e *Engine) stateCleanupLoop() {
	ticker := time.NewTicker(e.stateCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.stop:
			return
		case now := <-ticker.C:
			e.cleanupRetainedState(now)
		}
	}
}

func (e *Engine) cleanupRetainedState(now time.Time) {
	e.cleanupMetricState(now)

	e.profilesMu.Lock()
	profileCutoff := now.Add(-e.profilesTTL)
	for key, profile := range e.behavioralProfiles {
		if profile.LastSeen.Before(profileCutoff) || profile.LastSeen.After(now.Add(5*time.Minute)) {
			delete(e.behavioralProfiles, key)
		}
	}
	profileCount := len(e.behavioralProfiles)
	e.profilesMu.Unlock()

	e.ewmaMu.Lock()
	ewmaCutoff := now.Add(-e.metricsTTL)
	for key, state := range e.ewmaMap {
		if state == nil || state.LastTime.Before(ewmaCutoff) {
			delete(e.ewmaMap, key)
		}
	}
	ewmaCount := len(e.ewmaMap)
	e.ewmaMu.Unlock()

	e.logThrottleMu.Lock()
	logCutoff := now.Add(-5 * time.Minute)
	for key, seen := range e.logThrottle {
		if seen.Before(logCutoff) {
			delete(e.logThrottle, key)
		}
	}
	logCount := len(e.logThrottle)
	e.logThrottleMu.Unlock()

	e.preDetectionBufferMu.Lock()
	preDetectionCutoff := now.Add(-15 * time.Minute)
	for ip, seen := range e.preDetectionLastSeen {
		if seen.Before(preDetectionCutoff) {
			delete(e.preDetectionLastSeen, ip)
			delete(e.preDetectionBuffers, ip)
		}
	}
	preDetectionCount := len(e.preDetectionBuffers)
	e.preDetectionBufferMu.Unlock()

	e.detectionsMu.Lock()
	e.pruneLatestDetectionsLocked(now, true)
	latestCount := len(e.latestDetectionKeys)
	e.detectionsMu.Unlock()

	e.historyMu.Lock()
	e.pruneDetectionHistoryLocked(now)
	historyCount := len(e.detectionHistory)
	e.historyMu.Unlock()

	historyManagerCount := 0
	if e.historyManager != nil {
		e.historyManager.Cleanup(now)
		historyManagerCount = e.historyManager.Count()
	}

	stateCounts := map[string]int{
		"behavioral_profiles": profileCount,
		"ewma":                ewmaCount,
		"log_throttle":        logCount,
		"pre_detection":       preDetectionCount,
		"latest_detections":   latestCount,
		"detection_history":   historyCount,
		"event_histories":     historyManagerCount,
	}
	for component, count := range stateCounts {
		metrics.AIStateEntries.WithLabelValues(component).Set(float64(count))
	}
}

func (e *Engine) cleanupMetricState(now time.Time) {
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()
	cutoff := now.Add(-e.metricsTTL)
	for entityID, seen := range e.metricsLastSeen {
		if !seen.Before(cutoff) {
			continue
		}
		delete(e.metricsLastSeen, entityID)
		entityType, key, ok := strings.Cut(entityID, ":")
		if !ok {
			continue
		}
		switch entityType {
		case "ip":
			delete(e.signalsByIP, key)
			delete(e.detectionsByIP, key)
			delete(e.signalTypesByIP, key)
			delete(e.signalSourcesByIP, key)
		case "asn":
			delete(e.signalsByASN, key)
			delete(e.detectionsByASN, key)
			delete(e.signalTypesByASN, key)
			delete(e.signalSourcesByASN, key)
		case "ja4h":
			delete(e.signalsByJA4H, key)
			delete(e.detectionsByJA4H, key)
			delete(e.signalTypesByJA4H, key)
			delete(e.signalSourcesByJA4H, key)
		}
	}
	metrics.AIStateEntries.WithLabelValues("metric_entities").Set(float64(len(e.metricsLastSeen)))
}
