package patterns

import (
	"math"
	"net"
	"sync"
	"time"

	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/utils/mapcleaner"
	"PacketYeeter/pkg/utils/stats"
)

// ConnectionPattern tracks network-level behavioral patterns for bot detection
type ConnectionPattern struct {
	IP                   net.IP
	FirstSeen            time.Time
	LastSeen             time.Time
	ConnectionAttempts   uint64
	SuccessfulConns      uint64
	IncompleteHandshakes uint64

	// Packet Analysis
	PacketSizes   []uint16
	PacketTimings []time.Duration
	TTLValues     []uint8
	WindowSizes   []uint16
	MSSValues     []uint16

	// Port Scanning Detection
	PortsAccessed map[uint16]uint64 // port -> count
	PortSequence  []uint16          // Order of port access
	LastPortTime  time.Time

	// Geographic Tracking
	LastLocation    string // ASN or country
	LocationChanges uint64

	// Connection Reuse Tracking
	ConnectionIDs      []string        // Unique connection identifiers (src:dst:port combinations)
	ReuseTimings       []time.Duration // Time between connection reuses
	LastConnectionID   string
	LastConnectionTime time.Time
	ReuseCount         uint64
	RapidReuseCount    uint64 // Reuse within 1 second (suspicious)
}

// PatternTracker monitors network patterns for bot detection
type PatternTracker struct {
	mu       sync.RWMutex
	patterns map[string]*ConnectionPattern // IP -> pattern
	aiEngine *aidetection.Engine

	// Configuration
	maxPatterns         int
	patternExpiry       time.Duration
	uniformityThreshold float64
	portScanThreshold   uint64
	portScanWindow      time.Duration
}

func NewPatternTracker(aiEngine *aidetection.Engine) *PatternTracker {
	return &PatternTracker{
		patterns:            make(map[string]*ConnectionPattern),
		aiEngine:            aiEngine,
		maxPatterns:         100000,
		patternExpiry:       30 * time.Minute,
		uniformityThreshold: 0.85, // 85% packet sizes within 10% range = bot-like
		portScanThreshold:   20,   // 20 different ports in short time = scanning
		portScanWindow:      30 * time.Second,
	}
}

// ConnectionMetadata contains metadata about a connection
type ConnectionMetadata struct {
	PacketSize            uint16
	TTL                   uint8
	WindowSize            uint16
	MSS                   uint16
	DestPort              uint16
	IsIncompleteHandshake bool
	IsSuccessful          bool
	ASN                   string
	ConnectionID          string // Unique connection identifier (for reuse tracking)
}

// RecordConnection tracks a connection attempt with detailed metrics
func (pt *PatternTracker) RecordConnection(ip net.IP, meta ConnectionMetadata) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	ipStr := ip.String()
	pattern, exists := pt.patterns[ipStr]
	if !exists {
		pattern = &ConnectionPattern{
			IP:            ip,
			FirstSeen:     time.Now(),
			PortsAccessed: make(map[uint16]uint64),
		}
		pt.patterns[ipStr] = pattern

		// Enforce max patterns
		if len(pt.patterns) > pt.maxPatterns {
			pt.evictOldestPattern()
		}
	}

	pattern.LastSeen = time.Now()
	pattern.ConnectionAttempts++

	// Track packet characteristics
	if meta.PacketSize > 0 {
		pattern.PacketSizes = append(pattern.PacketSizes, meta.PacketSize)
		if len(pattern.PacketSizes) > 100 {
			pattern.PacketSizes = pattern.PacketSizes[1:]
		}
	}

	if meta.TTL > 0 {
		pattern.TTLValues = append(pattern.TTLValues, meta.TTL)
		if len(pattern.TTLValues) > 50 {
			pattern.TTLValues = pattern.TTLValues[1:]
		}
	}

	if meta.WindowSize > 0 {
		pattern.WindowSizes = append(pattern.WindowSizes, meta.WindowSize)
		if len(pattern.WindowSizes) > 50 {
			pattern.WindowSizes = pattern.WindowSizes[1:]
		}
	}

	if meta.MSS > 0 {
		pattern.MSSValues = append(pattern.MSSValues, meta.MSS)
		if len(pattern.MSSValues) > 50 {
			pattern.MSSValues = pattern.MSSValues[1:]
		}
	}

	// Track timing
	if len(pattern.PacketTimings) > 0 {
		timing := time.Since(pattern.LastSeen)
		pattern.PacketTimings = append(pattern.PacketTimings, timing)
		if len(pattern.PacketTimings) > 100 {
			pattern.PacketTimings = pattern.PacketTimings[1:]
		}
	}

	// Port scanning detection
	if meta.DestPort > 0 {
		pattern.PortsAccessed[meta.DestPort]++
		pattern.PortSequence = append(pattern.PortSequence, meta.DestPort)
		if len(pattern.PortSequence) > 100 {
			pattern.PortSequence = pattern.PortSequence[1:]
		}
		pattern.LastPortTime = time.Now()
	}

	// Track handshake completion
	if meta.IsIncompleteHandshake {
		pattern.IncompleteHandshakes++
	} else if meta.IsSuccessful {
		pattern.SuccessfulConns++
	}

	// Geographic tracking
	if meta.ASN != "" && meta.ASN != pattern.LastLocation {
		if pattern.LastLocation != "" {
			pattern.LocationChanges++
		}
		pattern.LastLocation = meta.ASN
	}

	// Connection reuse tracking
	if meta.ConnectionID != "" {
		now := time.Now()

		// Check if this is a reused connection
		if meta.ConnectionID == pattern.LastConnectionID {
			pattern.ReuseCount++

			// Calculate time since last reuse
			if !pattern.LastConnectionTime.IsZero() {
				reuseDelay := now.Sub(pattern.LastConnectionTime)
				pattern.ReuseTimings = append(pattern.ReuseTimings, reuseDelay)
				if len(pattern.ReuseTimings) > 50 {
					pattern.ReuseTimings = pattern.ReuseTimings[1:]
				}

				// Rapid reuse (< 1 second) is suspicious
				if reuseDelay < time.Second {
					pattern.RapidReuseCount++
				}
			}
		}

		// Track connection ID
		pattern.ConnectionIDs = append(pattern.ConnectionIDs, meta.ConnectionID)
		if len(pattern.ConnectionIDs) > 100 {
			pattern.ConnectionIDs = pattern.ConnectionIDs[1:]
		}
		pattern.LastConnectionID = meta.ConnectionID
		pattern.LastConnectionTime = now
	}

	// Analyze patterns and emit signals
	pt.analyzePattern(pattern)
}

func (pt *PatternTracker) analyzePattern(pattern *ConnectionPattern) {
	if pt.aiEngine == nil {
		return
	}

	now := time.Now()

	// 1. TTL Anomaly Detection
	if len(pattern.TTLValues) >= 10 {
		if pt.detectTTLAnomaly(pattern.TTLValues) {
			pt.aiEngine.EmitSignal(aidetection.Signal{
				Type:      aidetection.SignalTTLAnomaly,
				Source:    aidetection.SourceTCP,
				IP:        pattern.IP,
				Weight:    15.0,
				Timestamp: now,
				Metadata: map[string]interface{}{
					"ttl_values": pattern.TTLValues[len(pattern.TTLValues)-10:],
					"detail":     "Inconsistent TTL values suggest proxying or spoofing",
				},
			})
		}
	}

	// 2. Window Size Anomaly
	if len(pattern.WindowSizes) >= 10 {
		if pt.detectWindowAnomaly(pattern.WindowSizes) {
			pt.aiEngine.EmitSignal(aidetection.Signal{
				Type:      aidetection.SignalWindowAnomaly,
				Source:    aidetection.SourceTCP,
				IP:        pattern.IP,
				Weight:    3.0,
				Timestamp: now,
				Metadata: map[string]interface{}{
					"windows": pattern.WindowSizes[len(pattern.WindowSizes)-10:],
					"detail":  "Unusual TCP window sizes",
				},
			})
		}
	}

	// 3. Packet Size Uniformity (bot-like behavior)
	if len(pattern.PacketSizes) >= 20 {
		uniformity := pt.calculateUniformity(pattern.PacketSizes)
		if uniformity > pt.uniformityThreshold {
			pt.aiEngine.EmitSignal(aidetection.Signal{
				Type:      aidetection.SignalPacketSizeUniform,
				Source:    aidetection.SourceTCP,
				IP:        pattern.IP,
				Weight:    20.0,
				Timestamp: now,
				Metadata: map[string]interface{}{
					"uniformity":  uniformity,
					"sample_size": len(pattern.PacketSizes),
					"detail":      "Highly uniform packet sizes indicate automated traffic",
				},
			})
		}
	}

	// 4. Timing Pattern Analysis (mechanical timing)
	if len(pattern.PacketTimings) >= 20 {
		if pt.detectMechanicalTiming(pattern.PacketTimings) {
			pt.aiEngine.EmitSignal(aidetection.Signal{
				Type:      aidetection.SignalTimingPattern,
				Source:    aidetection.SourceTCP,
				IP:        pattern.IP,
				Weight:    25.0,
				Timestamp: now,
				Metadata: map[string]interface{}{
					"detail": "Mechanical timing pattern detected (bot-like)",
				},
			})
		}
	}

	// 5. Port Scanning Detection
	recentPorts := pt.getRecentPorts(pattern)
	if uint64(len(recentPorts)) > pt.portScanThreshold {
		isSequential := pt.isSequentialPorts(pattern.PortSequence)
		pt.aiEngine.EmitSignal(aidetection.Signal{
			Type:      aidetection.SignalPortScanning,
			Source:    aidetection.SourceTCP,
			IP:        pattern.IP,
			Weight:    40.0,
			Timestamp: now,
			Metadata: map[string]interface{}{
				"port_count":    len(recentPorts),
				"is_sequential": isSequential,
				"window":        pt.portScanWindow.String(),
				"detail":        "Port scanning activity detected",
			},
		})
	}

	// 6. Incomplete Handshake Pattern (SYN flood)
	if pattern.ConnectionAttempts >= 50 {
		incompleteRate := float64(pattern.IncompleteHandshakes) / float64(pattern.ConnectionAttempts)
		if incompleteRate > 0.7 { // 70% incomplete
			pt.aiEngine.EmitSignal(aidetection.Signal{
				Type:      aidetection.SignalIncompleteHandshake,
				Source:    aidetection.SourceTCP,
				IP:        pattern.IP,
				Weight:    35.0,
				Timestamp: now,
				Metadata: map[string]interface{}{
					"incomplete_rate": incompleteRate,
					"total_attempts":  pattern.ConnectionAttempts,
					"detail":          "High rate of incomplete handshakes (potential SYN flood)",
				},
			})
		}
	}

	// 7. Geographic Anomaly
	if pattern.LocationChanges >= 3 {
		duration := time.Since(pattern.FirstSeen)
		if duration < 10*time.Minute { // 3+ location changes in 10 minutes
			pt.aiEngine.EmitSignal(aidetection.Signal{
				Type:      aidetection.SignalGeoAnomaly,
				Source:    aidetection.SourceTCP,
				IP:        pattern.IP,
				Weight:    30.0,
				Timestamp: now,
				Metadata: map[string]interface{}{
					"location_changes": pattern.LocationChanges,
					"duration":         duration.String(),
					"detail":           "Rapid geographic location changes (impossible travel)",
				},
			})
		}
	}

	// 8. Connection Reuse Pattern Analysis
	if pattern.ReuseCount >= 10 {
		// High rapid reuse rate is suspicious (bots aggressively reusing connections)
		rapidReuseRate := float64(pattern.RapidReuseCount) / float64(pattern.ReuseCount)
		if rapidReuseRate > 0.6 { // 60% rapid reuse
			pt.aiEngine.EmitSignal(aidetection.Signal{
				Type:      aidetection.SignalConnectionReuse,
				Source:    aidetection.SourceTCP,
				IP:        pattern.IP,
				Weight:    25.0,
				Timestamp: now,
				Metadata: map[string]interface{}{
					"reuse_count":       pattern.ReuseCount,
					"rapid_reuse_count": pattern.RapidReuseCount,
					"rapid_reuse_rate":  rapidReuseRate,
					"detail":            "Aggressive connection reuse pattern (bot-like behavior)",
				},
			})
		}

		// Analyze reuse timing patterns
		if len(pattern.ReuseTimings) >= 10 {
			if pt.isMechanicalReuseTiming(pattern.ReuseTimings) {
				pt.aiEngine.EmitSignal(aidetection.Signal{
					Type:      aidetection.SignalConnectionReuse,
					Source:    aidetection.SourceTCP,
					IP:        pattern.IP,
					Weight:    20.0,
					Timestamp: now,
					Metadata: map[string]interface{}{
						"reuse_count":   pattern.ReuseCount,
						"timing_std_ms": pt.calculateStdDev(pattern.ReuseTimings),
						"detail":        "Mechanical connection reuse timing (scripted behavior)",
					},
				})
			}
		}
	}
}

// Helper functions for pattern analysis

// ttlAnomalyHopThreshold is how many hops a sample must deviate from the
// window's dominant TTL before it counts as an outlier. Real IP spoofing or
// proxy-pool rotation tends to cross OS-default TTL boundaries (Linux 64,
// Windows 128, some network gear 255), producing jumps of dozens of hops.
// Natural path diversity - anycast edge routing, ECMP load balancing,
// occasional BGP reconvergence - can easily shift a single source's observed
// TTL by a handful of hops with no spoofing involved at all; production
// traffic from Meta's globally distributed crawler infrastructure showed
// exactly this, with TTLs clustered tightly (e.g. 41-47) but occasionally
// spanning just over the old 5-hop threshold.
const ttlAnomalyHopThreshold = 20

// minTTLOutliersToFlag requires more than one deviating sample before
// flagging. A single malformed/glitched packet shouldn't condemn an
// otherwise perfectly consistent window.
const minTTLOutliersToFlag = 2

func (pt *PatternTracker) detectTTLAnomaly(ttls []uint8) bool {
	if len(ttls) < 10 {
		return false
	}

	// Find the dominant (most common) TTL in the window, then count how
	// many samples deviate meaningfully from it. This avoids the old
	// min/max approach, where a single outlier sample could blow out the
	// whole window's range even though the rest of the traffic was
	// perfectly consistent.
	counts := make(map[uint8]int, len(ttls))
	var mode uint8
	modeCount := 0
	for _, ttl := range ttls {
		counts[ttl]++
		if counts[ttl] > modeCount {
			modeCount = counts[ttl]
			mode = ttl
		}
	}

	outliers := 0
	for _, ttl := range ttls {
		diff := int(ttl) - int(mode)
		if diff < 0 {
			diff = -diff
		}
		if diff > ttlAnomalyHopThreshold {
			outliers++
		}
	}

	return outliers >= minTTLOutliersToFlag
}

func (pt *PatternTracker) detectWindowAnomaly(windows []uint16) bool {
	if len(windows) < 10 {
		return false
	}

	// Detect suspicious patterns: all zeros, all same unusual value
	allSame := true
	firstWindow := windows[0]

	for i := 1; i < len(windows); i++ {
		if windows[i] != firstWindow {
			allSame = false
			break
		}
	}

	if !allSame {
		return false
	}

	// A single source presenting the exact same advertised window size
	// across every connection is normal, expected TCP behavior, not a bot
	// signal: the value is derived from that client's OS/socket-buffer
	// configuration (and, with window scaling in play, essentially any
	// nonzero value is possible) and simply won't change unless the
	// client's receive buffer usage does. Real production traffic showed
	// this firing on ordinary VPS/hosting-provider clients whose stack
	// consistently advertised one plausible, if uncommon, window value -
	// a false positive, since a stable window is exactly what a single
	// real TCP stack looks like. The only "all same" cases worth flagging
	// are a window of zero (a stalled/malformed connection) or a window
	// so small it's characteristic of bare raw-socket scanning tools that
	// never configure a real TCP stack at all.
	return firstWindow == 0 || firstWindow < minPlausibleWindowSize
}

// minPlausibleWindowSize is the smallest advertised TCP window size we'd
// expect from any real OS network stack (browsers, servers, mobile
// devices). Values below this are typical of minimal raw-socket tooling
// (scanners, crude bots) rather than legitimate clients.
const minPlausibleWindowSize = 200

func (pt *PatternTracker) calculateUniformity(sizes []uint16) float64 {
	if len(sizes) < 2 {
		return 0.0
	}

	// Calculate mean
	var sum uint64
	for _, size := range sizes {
		sum += uint64(size)
	}
	mean := float64(sum) / float64(len(sizes))

	// Count how many are within 10% of mean
	threshold := mean * 0.1
	withinRange := 0
	for _, size := range sizes {
		if math.Abs(float64(size)-mean) <= threshold {
			withinRange++
		}
	}

	return float64(withinRange) / float64(len(sizes))
}

func (pt *PatternTracker) detectMechanicalTiming(timings []time.Duration) bool {
	if len(timings) < 20 {
		return false
	}

	// Check for highly regular intervals (variance < 5% of mean)
	var sum time.Duration
	for _, t := range timings {
		sum += t
	}
	mean := sum / time.Duration(len(timings))

	if mean == 0 {
		return false
	}

	// Calculate variance
	var varianceSum float64
	for _, t := range timings {
		diff := float64(t - mean)
		varianceSum += diff * diff
	}
	variance := varianceSum / float64(len(timings))
	stdDev := math.Sqrt(variance)

	coefficientOfVariation := stdDev / float64(mean)

	// Mechanical timing has very low coefficient of variation (<0.05)
	return coefficientOfVariation < 0.05 && mean > time.Millisecond
}

func (pt *PatternTracker) getRecentPorts(pattern *ConnectionPattern) map[uint16]bool {
	if time.Since(pattern.LastPortTime) > pt.portScanWindow {
		return make(map[uint16]bool)
	}

	// Count unique ports
	uniquePorts := make(map[uint16]bool)
	for port := range pattern.PortsAccessed {
		uniquePorts[port] = true
	}
	return uniquePorts
}

func (pt *PatternTracker) isSequentialPorts(sequence []uint16) bool {
	if len(sequence) < 10 {
		return false
	}

	sequential := 0
	checkLen := len(sequence)
	if checkLen > 50 {
		checkLen = 50
	}

	for i := 1; i < checkLen; i++ {
		diff := int(sequence[i]) - int(sequence[i-1])
		if diff == 1 || diff == -1 {
			sequential++
		}
	}

	// If more than 60% are sequential
	return float64(sequential)/float64(checkLen-1) > 0.6
}

func (pt *PatternTracker) evictOldestPattern() {
	mapcleaner.RemoveOldestEntry(pt.patterns, func(_ string, pattern *ConnectionPattern) time.Time {
		return pattern.LastSeen
	})
}

func (pt *PatternTracker) isMechanicalReuseTiming(timings []time.Duration) bool {
	if len(timings) < 10 {
		return false
	}

	// Calculate coefficient of variation (std/mean)
	mean := pt.calculateMeanDuration(timings)
	std := pt.calculateStdDev(timings)

	if mean == 0 {
		return false
	}

	cv := std / float64(mean.Milliseconds())

	// Low coefficient of variation (<0.1) suggests mechanical timing
	return cv < 0.1
}

func (pt *PatternTracker) calculateMeanDuration(timings []time.Duration) time.Duration {
	return stats.CalculateMeanDuration(timings)
}

func (pt *PatternTracker) calculateStdDev(timings []time.Duration) float64 {
	return stats.CalculateStdDevDuration(timings)
}

// Cleanup removes expired patterns
func (pt *PatternTracker) Cleanup() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-pt.patternExpiry)
	mapcleaner.RemoveEntriesOlderThan(pt.patterns, cutoff, func(_ string, pattern *ConnectionPattern) time.Time {
		return pattern.LastSeen
	})
}

// StartCleanup runs periodic cleanup
func (pt *PatternTracker) StartCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			pt.Cleanup()
		}
	}()
}

// GetPattern returns the connection pattern for an IP (read-only)
func (pt *PatternTracker) GetPattern(ip net.IP) *ConnectionPattern {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	pattern, exists := pt.patterns[ip.String()]
	if !exists {
		return nil
	}

	// Return copy to prevent race conditions
	patternCopy := *pattern
	return &patternCopy
}
