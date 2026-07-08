package threatintel

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"PacketYeeter/pkg/metrics"

	"github.com/sirupsen/logrus"
)

// enrichWorkerCount bounds the number of concurrent goroutines performing
// outbound threat-intel lookups (currently Shodan InternetDB). Without a
// bound, a flood of many distinct/spoofed source IPs -- exactly the
// scenario this system exists to survive -- could otherwise spawn one
// goroutine and one outbound HTTP request per signal, exhausting local
// goroutines/file descriptors and risking the analyzer's own egress IP
// being rate-limited by the upstream threat intel source.
const enrichWorkerCount = 16

// enrichQueueSize bounds how many pending enrichment requests can be
// buffered before new requests are dropped (enrichment is best-effort;
// dropping is safe and preferable to unbounded growth).
const enrichQueueSize = 2048

// ThreatIntelligence aggregates multiple threat intelligence sources
type ThreatIntelligence struct {
	shodan *ShodanInternetDB

	// IP enrichment cache - stores analyzed threat data
	mu              sync.RWMutex
	enrichmentCache map[string]*EnrichedIPInfo
	enrichmentTTL   time.Duration

	// Bounded worker pool for enrichment lookups, plus in-flight
	// deduplication so a burst of repeated signals for the same
	// not-yet-cached IP doesn't queue redundant lookups.
	enrichQueue chan net.IP
	inFlightMu  sync.Mutex
	inFlight    map[string]struct{}
}

// EnrichedIPInfo contains aggregated threat intelligence
type EnrichedIPInfo struct {
	IP              string
	IsKnownScanner  bool
	IsCloud         bool
	IsTor           bool
	IsVPN           bool
	OpenPorts       int
	Vulnerabilities int
	ThreatScore     float64 // 0-100, higher = more suspicious
	Tags            []string
	LastUpdated     time.Time
	Sources         []string // Which sources contributed
}

// NewThreatIntelligence creates a new threat intelligence aggregator
func NewThreatIntelligence() *ThreatIntelligence {
	ti := &ThreatIntelligence{
		shodan:          NewShodanInternetDB(24 * time.Hour),
		enrichmentCache: make(map[string]*EnrichedIPInfo),
		enrichmentTTL:   12 * time.Hour, // Re-enrich every 12 hours
		enrichQueue:     make(chan net.IP, enrichQueueSize),
		inFlight:        make(map[string]struct{}),
	}

	// Start background enrichment cleanup
	go ti.cleanupLoop()

	// Start a bounded pool of enrichment workers instead of spawning one
	// goroutine per signal (see enrichWorkerCount for why).
	for i := 0; i < enrichWorkerCount; i++ {
		go ti.enrichWorker()
	}

	logrus.WithField("workers", enrichWorkerCount).Info("Threat Intelligence initialized (Shodan InternetDB)")
	return ti
}

// EnrichIP requests an async threat intelligence lookup for ip. It is
// non-blocking: if the bounded enrichment queue is full, or a lookup for
// this IP is already in flight, the request is dropped (enrichment is
// best-effort and safe to skip -- it never gates blocking decisions).
func (t *ThreatIntelligence) EnrichIP(ip net.IP) {
	if ip == nil {
		return
	}

	ipStr := ip.String()

	// Check if already enriched recently
	t.mu.RLock()
	cached, ok := t.enrichmentCache[ipStr]
	t.mu.RUnlock()

	if ok && time.Since(cached.LastUpdated) < t.enrichmentTTL {
		return // Already fresh
	}

	// Deduplicate: don't queue another lookup for an IP that already has
	// one in flight (common under repeated signals for the same source
	// while the first lookup is still pending).
	t.inFlightMu.Lock()
	if _, already := t.inFlight[ipStr]; already {
		t.inFlightMu.Unlock()
		return
	}
	t.inFlight[ipStr] = struct{}{}
	t.inFlightMu.Unlock()

	select {
	case t.enrichQueue <- ip:
		metrics.ThreatIntelEnrichQueueDepth.Set(float64(len(t.enrichQueue)))
	default:
		// Queue full - drop and clear the in-flight marker so a future
		// signal for this IP can try again.
		t.inFlightMu.Lock()
		delete(t.inFlight, ipStr)
		t.inFlightMu.Unlock()
		metrics.ThreatIntelEnrichQueueDrops.Inc()
	}
}

// enrichWorker drains the bounded enrichment queue. A fixed pool of these
// run for the lifetime of the process, capping the number of concurrent
// outbound threat-intel lookups regardless of inbound signal volume.
func (t *ThreatIntelligence) enrichWorker() {
	for ip := range t.enrichQueue {
		t.performEnrichment(ip)
		t.inFlightMu.Lock()
		delete(t.inFlight, ip.String())
		t.inFlightMu.Unlock()
	}
}

// performEnrichment fetches data from all sources
func (t *ThreatIntelligence) performEnrichment(ip net.IP) {
	ipStr := ip.String()

	enriched := &EnrichedIPInfo{
		IP:          ipStr,
		LastUpdated: time.Now(),
		Sources:     []string{},
		Tags:        []string{},
	}

	// Query Shodan InternetDB
	shodanInfo, err := t.shodan.Lookup(ip)
	if err == nil && shodanInfo != nil {
		enriched.Sources = append(enriched.Sources, "shodan")
		enriched.IsKnownScanner = shodanInfo.IsScanner
		enriched.IsCloud = shodanInfo.IsCloud
		enriched.IsTor = shodanInfo.IsTor
		enriched.IsVPN = shodanInfo.IsVPN
		enriched.OpenPorts = shodanInfo.OpenPorts
		enriched.Vulnerabilities = len(shodanInfo.Vulns)
		enriched.Tags = append(enriched.Tags, shodanInfo.Tags...)

		// Calculate threat score
		enriched.ThreatScore = t.calculateThreatScore(shodanInfo)
	}

	// Store enriched data
	t.mu.Lock()
	t.enrichmentCache[ipStr] = enriched
	t.mu.Unlock()

	// Update metrics
	metrics.ThreatIntelEnrichments.Inc()
	if metrics.IsHighCardinalityEnabled() {
		if enriched.ThreatScore > 0 {
			metrics.ThreatIntelScore.WithLabelValues(ipStr).Observe(enriched.ThreatScore)
		}
		metrics.ThreatIntelInfo.WithLabelValues(
			ipStr,
			strings.Join(enriched.Sources, ","),
			strings.Join(enriched.Tags, ","),
			fmt.Sprintf("%d", enriched.OpenPorts),
			fmt.Sprintf("%t", enriched.IsKnownScanner),
			fmt.Sprintf("%t", enriched.IsCloud),
			fmt.Sprintf("%t", enriched.IsTor),
			fmt.Sprintf("%t", enriched.IsVPN),
			fmt.Sprintf("%.1f", enriched.ThreatScore),
		).Set(enriched.ThreatScore)
	}

	if len(enriched.Sources) > 0 {
		logrus.WithFields(logrus.Fields{
			"ip":           ipStr,
			"scanner":      enriched.IsKnownScanner,
			"cloud":        enriched.IsCloud,
			"threat_score": enriched.ThreatScore,
			"sources":      enriched.Sources,
		}).Debug("IP enriched")
	}
}

// calculateThreatScore computes a threat score from Shodan data
func (t *ThreatIntelligence) calculateThreatScore(info *ShodanIPInfo) float64 {
	score := 0.0

	// Known scanner = high suspicion
	if info.IsScanner {
		score += 40.0
	}

	// Many open ports = potential scanner/bot
	if info.OpenPorts > 10 {
		score += 20.0
	} else if info.OpenPorts > 5 {
		score += 10.0
	}

	// Known vulnerabilities = compromised/vulnerable host
	if info.HasVulns {
		score += float64(len(info.Vulns)) * 5.0
		if score > 30.0 {
			score = 30.0 // Cap vuln contribution
		}
	}

	// Tor = anonymization (moderate suspicion)
	if info.IsTor {
		score += 15.0
	}

	// VPN/Proxy = anonymization (low suspicion)
	if info.IsVPN {
		score += 5.0
	}

	// Cloud = less suspicious (legitimate services)
	if info.IsCloud && !info.IsScanner {
		score -= 10.0
	}

	// Normalize to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// GetEnrichedInfo retrieves cached enrichment data
func (t *ThreatIntelligence) GetEnrichedInfo(ip net.IP) *EnrichedIPInfo {
	if ip == nil {
		return nil
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.enrichmentCache[ip.String()]
}

// IsKnownScanner checks if IP is a known scanner
func (t *ThreatIntelligence) IsKnownScanner(ip net.IP) bool {
	info := t.GetEnrichedInfo(ip)
	return info != nil && info.IsKnownScanner
}

// GetThreatScore returns threat score for an IP
func (t *ThreatIntelligence) GetThreatScore(ip net.IP) float64 {
	info := t.GetEnrichedInfo(ip)
	if info == nil {
		return 0.0
	}
	return info.ThreatScore
}

// cleanupLoop periodically removes old enrichment data
func (t *ThreatIntelligence) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanup()
	}
}

// cleanup removes stale enrichment data
func (t *ThreatIntelligence) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	maxAge := t.enrichmentTTL * 4 // Keep data for 4x TTL before deleting

	for ip, info := range t.enrichmentCache {
		if now.Sub(info.LastUpdated) > maxAge {
			delete(t.enrichmentCache, ip)
		}
	}

	logrus.WithField("cache_size", len(t.enrichmentCache)).Debug("Threat intel cache cleanup")
}

// GetStats returns statistics
func (t *ThreatIntelligence) GetStats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	scanners := 0
	cloud := 0
	tor := 0
	highThreat := 0

	for _, info := range t.enrichmentCache {
		if info.IsKnownScanner {
			scanners++
		}
		if info.IsCloud {
			cloud++
		}
		if info.IsTor {
			tor++
		}
		if info.ThreatScore > 50.0 {
			highThreat++
		}
	}

	shodanCache, shodanScanners, shodanCloud, shodanTor := t.shodan.GetStats()

	return map[string]interface{}{
		"enrichment_cache_size": len(t.enrichmentCache),
		"known_scanners":        scanners,
		"cloud_ips":             cloud,
		"tor_exits":             tor,
		"high_threat_ips":       highThreat,
		"shodan_cache_size":     shodanCache,
		"shodan_scanners":       shodanScanners,
		"shodan_cloud":          shodanCloud,
		"shodan_tor":            shodanTor,
	}
}
