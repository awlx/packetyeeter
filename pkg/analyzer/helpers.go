package analyzer

import (
	"net"
	"strings"
	"time"

	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/metrics"
)

// Contains performs a case-insensitive substring check
func Contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

var (
	blockedIPs  = make(map[string]time.Time)
	blockedASNs = make(map[string]time.Time)
)

func trackBlocked(ip net.IP, asn string) {
	now := time.Now()
	window := 60 * time.Second
	if ip != nil {
		blockedIPs[ip.String()] = now
	}
	if asn != "" && asn != "Unknown" {
		blockedASNs[asn] = now
	}
	// Cleanup
	cutoff := now.Add(-window)
	for k, ts := range blockedIPs {
		if ts.Before(cutoff) {
			delete(blockedIPs, k)
		}
	}
	for k, ts := range blockedASNs {
		if ts.Before(cutoff) {
			delete(blockedASNs, k)
		}
	}
	metrics.RateLimitCurrentlyBlockedIPs.Set(float64(len(blockedIPs)))
	metrics.RateLimitCurrentlyBlockedASNs.Set(float64(len(blockedASNs)))
}

// checkRateLimit checks if IP or ASN has exceeded rate limits
func (a *Analyzer) checkRateLimit(ip net.IP, asn string) bool {
	if a.RateLimiter == nil {
		return false
	}

	// Active counts (post-cleanup) reflect recent entities (maxAge=10m)
	ipCnt, asnCnt := a.RateLimiter.GetStats()
	metrics.RateLimitActiveIPs.Set(float64(ipCnt))
	metrics.RateLimitActiveASNs.Set(float64(asnCnt))

	// Enforce limiter
	allowed := a.RateLimiter.Allow(ip, asn)
	if !allowed {
		if ip != nil {
			metrics.RateLimitExceeded.WithLabelValues("ip").Inc()
		}
		if asn != "" && asn != "Unknown" {
			metrics.RateLimitExceeded.WithLabelValues("asn").Inc()
		}
		if !a.Config.DryRun {
			trackBlocked(ip, asn)
		}
	}
	return !allowed
}

// extractMLFeatures extracts features for ML model prediction
func (a *Analyzer) extractMLFeatures(ip net.IP, asn string, reputationScore float64) aidetection.MLFeatures {
	features := aidetection.MLFeatures{
		SignalCount:     0,
		SignalDiversity: 0,
		SignalRate:      0,
		ReputationScore: reputationScore,
		HasASN:          asn != "" && asn != "Unknown",
	}

	// Get pattern data if available
	if a.PatternTracker != nil {
		pattern := a.PatternTracker.GetPattern(ip)
		if pattern != nil {
			features.SignalCount = int(pattern.ConnectionAttempts)
			features.SignalDiversity = len(pattern.PortsAccessed)

			// Calculate signal rate
			if !pattern.FirstSeen.IsZero() {
				duration := time.Since(pattern.FirstSeen).Seconds()
				if duration > 0 {
					features.SignalRate = float64(pattern.ConnectionAttempts) / duration
				}
			}

			// Check for timing patterns
			features.IsBursty = len(pattern.PacketTimings) > 5
		}
	}

	// Get threat intel if available
	if a.ThreatIntel != nil {
		enriched := a.ThreatIntel.GetEnrichedInfo(ip)
		if enriched != nil {
			features.ThreatScore = enriched.ThreatScore
			features.IsKnownScanner = enriched.IsKnownScanner
			features.IsTor = enriched.IsTor
			features.IsVPN = enriched.IsVPN
			features.IsCloud = enriched.IsCloud
			features.HasVulnerabilities = enriched.Vulnerabilities > 0
			features.OpenPortCount = enriched.OpenPorts
		}
	}

	return features
}
