package analyzer

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/metrics"
)

// Contains performs a case-insensitive substring check
func Contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// mlConfirmsReputationBlock applies the optional ML veto consistently across
// transport and HTTP reputation blocks. A nil model means the operator did not
// configure -ml-model, so reputation remains the sole decision source.
func (a *Analyzer) mlConfirmsReputationBlock(ip net.IP, asn string, score float64, source string) bool {
	if a.MLModel == nil {
		return true
	}

	prediction := a.MLModel.Predict(a.extractMLFeatures(ip, asn, score))
	confirmed := prediction.IsBot && prediction.Confidence >= a.Config.AIConfidenceThreshold
	if !confirmed {
		metrics.MLBlocksOverridden.Inc()
	}

	logrus.WithFields(logrus.Fields{
		"ip":            ip.String(),
		"reputation":    score,
		"ml_confidence": prediction.Confidence,
		"ml_category":   prediction.Category,
		"ml_tier":       prediction.ModelTier,
		"source":        source,
	}).Debug("ML reputation-block decision")

	return confirmed
}

// blockedMu guards blockedIPs and blockedASNs: trackBlocked runs concurrently
// from the per-collector gRPC stream handler goroutines.
var (
	blockedMu   sync.Mutex
	blockedIPs  = make(map[string]time.Time)
	blockedASNs = make(map[string]time.Time)
)

func trackBlocked(ip net.IP, asn string) {
	now := time.Now()
	window := 60 * time.Second
	blockedMu.Lock()
	defer blockedMu.Unlock()
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
		// HybridModel's pattern-checker contract carries the ASN in this
		// legacy field; keep the direct reputation gate consistent with the
		// AI engine's feature extraction.
		GeoCountry: asn,
	}

	// Get pattern data if available. Use the narrow summary accessor rather
	// than GetPattern: the feature extractor only needs these four fields, so
	// there is no reason to deep-copy the pattern's nine slices/maps per signal.
	if a.PatternTracker != nil {
		if s, ok := a.PatternTracker.PatternSummary(ip); ok {
			features.SignalCount = int(s.ConnectionAttempts)
			features.SignalDiversity = s.PortsAccessed

			// Calculate signal rate
			if !s.FirstSeen.IsZero() {
				duration := time.Since(s.FirstSeen).Seconds()
				if duration > 0 {
					features.SignalRate = float64(s.ConnectionAttempts) / duration
				}
			}

			// Check for timing patterns: bursty = irregular/clustered spacing
			// between connections (high coefficient of variation), not merely
			// "has more than a few samples".
			features.IsBursty = s.Bursty
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
