package clockskew

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

// maxPlausibleSkewPPM bounds the magnitude of a computed skew value we treat
// as real clock drift. See ProcessTimestamp for why values beyond this are
// rejected rather than reported.
const maxPlausibleSkewPPM = 50000.0

// Profile tracks TCP timestamp behavior for clock skew detection
type Profile struct {
	IP              string
	FirstTimestamp  uint32 // First TSval observed
	LastTimestamp   uint32 // Most recent TSval
	FirstObservedAt time.Time
	LastObservedAt  time.Time
	Observations    int
	SkewPPM         float64 // Parts per million drift
	LastSkewPPM     float64
	SkewChanges     int // Count of significant skew changes
}

// Analyzer detects TCP timestamp clock skew anomalies
type Analyzer struct {
	profiles      map[string]*Profile
	mu            sync.RWMutex
	aiEngine      *aidetection.Engine
	maxProfiles   int
	cleanupTicker *time.Ticker

	logThrottle map[string]time.Time
	logMu       sync.Mutex
}

func NewAnalyzer(aiEngine *aidetection.Engine) *Analyzer {
	return &Analyzer{
		profiles:    make(map[string]*Profile),
		aiEngine:    aiEngine,
		maxProfiles: 10000,
		logThrottle: make(map[string]time.Time),
	}
}

func (a *Analyzer) Start() {
	a.cleanupTicker = time.NewTicker(5 * time.Minute)
	go a.cleanupLoop()
}

func (a *Analyzer) Stop() {
	if a.cleanupTicker != nil {
		a.cleanupTicker.Stop()
	}
}

func (a *Analyzer) cleanupLoop() {
	for range a.cleanupTicker.C {
		a.cleanup()
	}
}

func (a *Analyzer) shouldLog(key string, ttl time.Duration) bool {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	now := time.Now()
	if prev, ok := a.logThrottle[key]; ok {
		if now.Sub(prev) < ttl {
			return false
		}
	}
	a.logThrottle[key] = now
	return true
}

func (a *Analyzer) cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Hour)
	mapcleaner.RemoveEntriesOlderThan(a.profiles, cutoff, func(_ string, profile *Profile) time.Time {
		return profile.LastObservedAt
	})

	metrics.ClockSkewProfiles.Set(float64(len(a.profiles)))
}

// ProcessTimestamp analyzes TCP timestamp for clock skew
func (a *Analyzer) ProcessTimestamp(srcIP net.IP, timestamp uint32) {
	if timestamp == 0 {
		return
	}

	ipStr := srcIP.String()
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	profile, exists := a.profiles[ipStr]
	if !exists {
		profile = &Profile{
			IP:              ipStr,
			FirstTimestamp:  timestamp,
			LastTimestamp:   timestamp,
			FirstObservedAt: now,
			LastObservedAt:  now,
			Observations:    1,
		}
		a.profiles[ipStr] = profile

		// Enforce max profiles
		if len(a.profiles) > a.maxProfiles {
			mapcleaner.RemoveOldestEntry(a.profiles, func(_ string, p *Profile) time.Time {
				return p.LastObservedAt
			})
		}

		metrics.ClockSkewProfiles.Set(float64(len(a.profiles)))
		return
	}

	// Detect per-connection TSval resets (timestamp decreased shortly after last)
	if timestamp < profile.LastTimestamp && now.Sub(profile.LastObservedAt) < 10*time.Second {
		profile.FirstTimestamp = timestamp
		profile.LastTimestamp = timestamp
		profile.FirstObservedAt = now
		profile.LastObservedAt = now
		profile.Observations = 1
		profile.SkewPPM = 0
		profile.LastSkewPPM = 0
		metrics.ClockSkewResets.Inc()
		return
	}

	profile.Observations++
	profile.LastTimestamp = timestamp
	profile.LastObservedAt = now

	metrics.ClockSkewObservations.Inc()

	// Need at least 2 observations to calculate skew
	if profile.Observations < 2 {
		return
	}

	// Calculate clock skew in parts per million (PPM)
	// Real time elapsed (in seconds)
	timeDelta := now.Sub(profile.FirstObservedAt).Seconds()

	// Require sufficient wall time to reduce jitter noise
	if timeDelta < 15 {
		return
	}

	// TCP timestamp delta (handling wraparound)
	var tsDelta float64
	if timestamp >= profile.FirstTimestamp {
		tsDelta = float64(timestamp - profile.FirstTimestamp)
	} else {
		// Wraparound occurred (32-bit timestamp wrapped)
		tsDelta = float64(uint64(0xFFFFFFFF-profile.FirstTimestamp) + uint64(timestamp) + 1)
	}

	// TCP timestamps typically increment at 1000 Hz (1ms resolution)
	// Expected timestamp delta based on real time
	expectedTsDelta := timeDelta * 1000.0

	if expectedTsDelta == 0 {
		return // Avoid division by zero
	}

	// Calculate skew in PPM
	skewPPM := ((tsDelta - expectedTsDelta) / expectedTsDelta) * 1000000.0

	// Reject implausible skew values before storing/emitting them. Real
	// oscillator drift is a few to a few hundred PPM even on poor-quality
	// hardware; values in the tens of thousands of PPM or beyond aren't a
	// "very bad clock" - they're almost always this profile actually
	// representing multiple different hosts/connections sharing one IP
	// under CGNAT (extremely common on large consumer/mobile ISPs), where
	// the tracked TSval sequence jumps between unrelated devices and
	// produces a skew computation that's mathematically valid but
	// physically meaningless. Left unfiltered, one such measurement also
	// poisons every subsequent skew-change comparison (since it's stored
	// as profile.SkewPPM and compared against on the next update), which
	// is why these values were previously seen recurring rather than
	// appearing once - so we reset the reference point instead of storing
	// it, the same way an observed TSval decrease is handled above.
	if math.Abs(skewPPM) > maxPlausibleSkewPPM {
		profile.FirstTimestamp = timestamp
		profile.FirstObservedAt = now
		profile.Observations = 1
		profile.SkewPPM = 0
		profile.LastSkewPPM = 0
		metrics.ClockSkewResets.Inc()
		return
	}

	// Update profile
	previousSkewPPM := profile.SkewPPM
	profile.LastSkewPPM = previousSkewPPM
	profile.SkewPPM = skewPPM

	// Emit metric
	if metrics.IsHighCardinalityEnabled() {
		metrics.ClockSkewPPM.WithLabelValues(ipStr).Observe(skewPPM)
	}

	// Detect significant changes in skew (> 500 PPM change)
	if math.Abs(skewPPM-previousSkewPPM) > 500.0 && profile.Observations >= 15 && timeDelta >= 30 {
		profile.SkewChanges++
		metrics.ClockSkewChanges.Inc()

		logrus.WithFields(logrus.Fields{
			"ip":           ipStr,
			"skew_ppm":     skewPPM,
			"previous_ppm": previousSkewPPM,
			"change_ppm":   math.Abs(skewPPM - previousSkewPPM),
			"observations": profile.Observations,
			"skew_changes": profile.SkewChanges,
		}).Debug("Clock skew change detected")

		if a.aiEngine != nil {
			a.aiEngine.EmitSignal(aidetection.Signal{
				Type:   aidetection.SignalClockSkewChange,
				Source: aidetection.SourceFingerprint,
				IP:     srcIP,
				Weight: 10.0,
				Metadata: map[string]interface{}{
					"skew_ppm":     skewPPM,
					"previous_ppm": previousSkewPPM,
					"observations": profile.Observations,
					"skew_changes": profile.SkewChanges,
				},
			})
		}
	}

	// Detect anomalous skew (> 10000 PPM absolute)
	// Require minimum observations/time to avoid false positives from initialization
	absSkew := math.Abs(skewPPM)
	if absSkew > 10000.0 && profile.Observations >= 20 && timeDelta >= 60 {
		metrics.ClockSkewAnomalies.Inc()

		if a.shouldLog(ipStr, 5*time.Minute) {
			logrus.WithFields(logrus.Fields{
				"ip":           ipStr,
				"skew_ppm":     skewPPM,
				"observations": profile.Observations,
			}).Info("High clock skew detected (VM migration, replay, or bot)")
		}

		if a.aiEngine != nil {
			weight := 10.0
			if absSkew > 20000.0 {
				weight = 15.0 // Very high skew = very suspicious
			}

			a.aiEngine.EmitSignal(aidetection.Signal{
				Type:   aidetection.SignalClockSkewAnomaly,
				Source: aidetection.SourceFingerprint,
				IP:     srcIP,
				Weight: weight,
				Metadata: map[string]interface{}{
					"skew_ppm":     skewPPM,
					"observations": profile.Observations,
					"time_delta":   timeDelta,
					"ts_delta":     tsDelta,
				},
			})
		}
	}
}

// GetStats returns statistics for monitoring
func (a *Analyzer) GetStats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"total_profiles": len(a.profiles),
	}
}
