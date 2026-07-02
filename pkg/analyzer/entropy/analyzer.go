package entropy

import (
	"math"
	"net"
	"sync"
	"time"

	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/utils/mapcleaner"

	"github.com/sirupsen/logrus"
)

// EntropyProfile tracks payload entropy behavior for an IP
type EntropyProfile struct {
	IP               string
	Observations     int
	EntropySum       float64
	EntropyMean      float64
	LowEntropyCount  int
	HighEntropyCount int
	LastObservedAt   time.Time
}

// EntropyAnalyzer detects payload entropy anomalies
type EntropyAnalyzer struct {
	profiles      map[string]*EntropyProfile
	mu            sync.RWMutex
	aiEngine      *aidetection.Engine
	maxProfiles   int
	cleanupTicker *time.Ticker
}

func NewEntropyAnalyzer(aiEngine *aidetection.Engine) *EntropyAnalyzer {
	return &EntropyAnalyzer{
		profiles:    make(map[string]*EntropyProfile),
		aiEngine:    aiEngine,
		maxProfiles: 10000,
	}
}

func (a *EntropyAnalyzer) Start() {
	a.cleanupTicker = time.NewTicker(5 * time.Minute)
	go a.cleanupLoop()
}

func (a *EntropyAnalyzer) Stop() {
	if a.cleanupTicker != nil {
		a.cleanupTicker.Stop()
	}
}

func (a *EntropyAnalyzer) cleanupLoop() {
	for range a.cleanupTicker.C {
		a.cleanup()
	}
}

func (a *EntropyAnalyzer) cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Hour)
	mapcleaner.RemoveEntriesOlderThan(a.profiles, cutoff, func(_ string, profile *EntropyProfile) time.Time {
		return profile.LastObservedAt
	})

	metrics.PayloadEntropyProfiles.Set(float64(len(a.profiles)))
}

// ProcessEntropy analyzes payload entropy score from eBPF
// entropyScore is 0-100 from the eBPF simplified estimation
func (a *EntropyAnalyzer) ProcessEntropy(srcIP net.IP, entropyScore uint8) {
	if entropyScore == 0 {
		return // No data to analyze
	}

	ipStr := srcIP.String()

	// Convert 0-100 score to approximate bits (0-8 scale)
	// This is a rough mapping since eBPF gives simplified score
	entropyBits := float64(entropyScore) * 8.0 / 100.0

	a.mu.Lock()
	defer a.mu.Unlock()

	profile, exists := a.profiles[ipStr]
	if !exists {
		profile = &EntropyProfile{
			IP:             ipStr,
			Observations:   0,
			LastObservedAt: time.Now(),
		}
		a.profiles[ipStr] = profile

		// Enforce max profiles
		if len(a.profiles) > a.maxProfiles {
			mapcleaner.RemoveOldestEntry(a.profiles, func(_ string, p *EntropyProfile) time.Time {
				return p.LastObservedAt
			})
		}

		metrics.PayloadEntropyProfiles.Set(float64(len(a.profiles)))
	}

	profile.Observations++
	profile.EntropySum += entropyBits
	profile.EntropyMean = profile.EntropySum / float64(profile.Observations)
	profile.LastObservedAt = time.Now()

	metrics.PayloadEntropyObservations.Inc()
	if metrics.IsHighCardinalityEnabled() {
		metrics.PayloadEntropyValue.WithLabelValues(ipStr).Observe(entropyBits)
	}

	// Detect low entropy (templated/repeated bot traffic)
	if entropyBits < 3.0 {
		profile.LowEntropyCount++
		metrics.PayloadEntropyLowCount.Inc()

		if profile.Observations > 5 {
			logrus.WithFields(logrus.Fields{
				"ip":            ipStr,
				"entropy_bits":  entropyBits,
				"entropy_score": entropyScore,
				"observations":  profile.Observations,
				"low_count":     profile.LowEntropyCount,
			}).Debug("Low entropy payload detected (templated bot traffic)")

			if a.aiEngine != nil {
				a.aiEngine.EmitSignal(aidetection.Signal{
					Type:   aidetection.SignalEntropyLow,
					Source: aidetection.SourceFingerprint,
					IP:     srcIP,
					Weight: 12.0,
					Metadata: map[string]interface{}{
						"entropy_bits":  entropyBits,
						"entropy_score": entropyScore,
						"mean_entropy":  profile.EntropyMean,
					},
				})
			}
		}
	}

	// Detect suspiciously uniform/high entropy (encrypted or randomized bot traffic)
	if entropyBits > 7.5 {
		profile.HighEntropyCount++
		metrics.PayloadEntropyUniformCount.Inc()

		if profile.Observations > 5 {
			logrus.WithFields(logrus.Fields{
				"ip":            ipStr,
				"entropy_bits":  entropyBits,
				"entropy_score": entropyScore,
				"observations":  profile.Observations,
				"high_count":    profile.HighEntropyCount,
			}).Debug("High/uniform entropy detected (encrypted or randomized)")

			if a.aiEngine != nil {
				// High entropy is less suspicious than low, but still worth tracking
				a.aiEngine.EmitSignal(aidetection.Signal{
					Type:   aidetection.SignalEntropyHigh,
					Source: aidetection.SourceFingerprint,
					IP:     srcIP,
					Weight: 5.0,
					Metadata: map[string]interface{}{
						"entropy_bits":  entropyBits,
						"entropy_score": entropyScore,
						"mean_entropy":  profile.EntropyMean,
					},
				})
			}
		}
	}

	// Detect unusual variance (mixing low and high entropy - bot fingerprint)
	if profile.Observations > 10 {
		lowRatio := float64(profile.LowEntropyCount) / float64(profile.Observations)
		highRatio := float64(profile.HighEntropyCount) / float64(profile.Observations)

		// If >30% of traffic is low entropy AND >30% is high entropy, suspicious
		if lowRatio > 0.3 && highRatio > 0.3 {
			variance := math.Abs(lowRatio - highRatio)
			if variance < 0.2 { // Both roughly equal = very suspicious
				logrus.WithFields(logrus.Fields{
					"ip":           ipStr,
					"low_ratio":    lowRatio,
					"high_ratio":   highRatio,
					"mean":         profile.EntropyMean,
					"observations": profile.Observations,
				}).Warn("Mixed entropy pattern detected (bot switching behaviors)")

				if a.aiEngine != nil {
					a.aiEngine.EmitSignal(aidetection.Signal{
						Type:   aidetection.SignalEntropyMixed,
						Source: aidetection.SourceFingerprint,
						IP:     srcIP,
						Weight: 18.0,
						Metadata: map[string]interface{}{
							"low_ratio":  lowRatio,
							"high_ratio": highRatio,
							"variance":   variance,
						},
					})
				}
			}
		}
	}
}

// GetStats returns statistics for monitoring
func (a *EntropyAnalyzer) GetStats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"total_profiles": len(a.profiles),
	}
}
