package aidetection

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"PacketYeeter/pkg/utils/ewma"
)

const (
	defaultCampaignBaselineTau               = 5 * time.Minute
	defaultCampaignBaselineMinSamples        = 5
	defaultCampaignBaselineMinRate           = 1.0
	defaultCampaignBaselineAnomalyMultiplier = 3.0
	defaultCampaignBaselineMaxKeys           = 4096
)

type CampaignBaselineConfig struct {
	Tau               time.Duration
	MinSamples        int
	MinRate           float64
	AnomalyMultiplier float64
	MaxKeys           int
}

func DefaultCampaignBaselineConfig() CampaignBaselineConfig {
	return CampaignBaselineConfig{
		Tau:               defaultCampaignBaselineTau,
		MinSamples:        defaultCampaignBaselineMinSamples,
		MinRate:           defaultCampaignBaselineMinRate,
		AnomalyMultiplier: defaultCampaignBaselineAnomalyMultiplier,
		MaxKeys:           defaultCampaignBaselineMaxKeys,
	}
}

func normalizeCampaignBaselineConfig(cfg CampaignBaselineConfig) CampaignBaselineConfig {
	def := DefaultCampaignBaselineConfig()
	if cfg.Tau == 0 {
		cfg.Tau = def.Tau
	}
	if cfg.MinSamples == 0 {
		cfg.MinSamples = def.MinSamples
	}
	if cfg.MinRate == 0 {
		cfg.MinRate = def.MinRate
	}
	if cfg.AnomalyMultiplier == 0 {
		cfg.AnomalyMultiplier = def.AnomalyMultiplier
	}
	if cfg.MaxKeys == 0 {
		cfg.MaxKeys = def.MaxKeys
	}
	return cfg
}

type CampaignBaselineObservation struct {
	ServiceKey        string
	Protocol          string
	DstPortBucket     string
	CurrentRate       float64
	BaselineRate      float64
	EffectiveBaseline float64
	Multiplier        float64
	Samples           int
	EnoughSamples     bool
	Anomalous         bool
}

type campaignBaselineState struct {
	rate     ewma.State
	samples  int
	lastSeen time.Time
}

type CampaignBaselineTracker struct {
	mu     sync.Mutex
	cfg    CampaignBaselineConfig
	states map[string]*campaignBaselineState
}

func NewCampaignBaselineTracker(cfg CampaignBaselineConfig) *CampaignBaselineTracker {
	return &CampaignBaselineTracker{
		cfg:    normalizeCampaignBaselineConfig(cfg),
		states: make(map[string]*campaignBaselineState),
	}
}

func (t *CampaignBaselineTracker) Observe(key CampaignBaselineKey, currentRate float64, now time.Time) CampaignBaselineObservation {
	if t == nil {
		return CampaignBaselineObservation{}
	}
	if now.IsZero() {
		now = time.Now()
	}
	if currentRate < 0 {
		currentRate = 0
	}

	serviceKey := key.String()
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.states) > t.cfg.MaxKeys {
		t.pruneLocked(now)
		if len(t.states) > t.cfg.MaxKeys {
			t.states = make(map[string]*campaignBaselineState)
		}
	}

	st := t.states[serviceKey]
	if st == nil {
		st = &campaignBaselineState{}
		t.states[serviceKey] = st
	}

	obs := CampaignBaselineObservation{
		ServiceKey:    serviceKey,
		Protocol:      key.Protocol,
		DstPortBucket: key.DstPortBucket,
		CurrentRate:   currentRate,
		BaselineRate:  st.rate.Value,
		Samples:       st.samples,
		EnoughSamples: st.samples >= t.cfg.MinSamples,
	}
	obs.EffectiveBaseline = obs.BaselineRate
	if obs.EffectiveBaseline < t.cfg.MinRate {
		obs.EffectiveBaseline = t.cfg.MinRate
	}
	if obs.EffectiveBaseline > 0 {
		obs.Multiplier = currentRate / obs.EffectiveBaseline
	}
	obs.Anomalous = obs.EnoughSamples && obs.Multiplier >= t.cfg.AnomalyMultiplier

	if st.samples == 0 || st.rate.LastTime.IsZero() {
		st.rate = ewma.State{Value: currentRate, LastTime: now}
	} else {
		updated := ewma.Update(st.rate, currentRate, now, t.cfg.Tau)
		st.rate = updated
	}
	st.samples++
	st.lastSeen = now

	return obs
}

func (t *CampaignBaselineTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-2 * t.cfg.Tau)
	for key, st := range t.states {
		if !st.lastSeen.IsZero() && st.lastSeen.Before(cutoff) {
			delete(t.states, key)
		}
	}
}

type CampaignBaselineKey struct {
	Protocol      string
	DstPortBucket string
	Vector        SignalType
}

func (k CampaignBaselineKey) String() string {
	protocol := k.Protocol
	if protocol == "" {
		protocol = "unknown"
	}
	portBucket := k.DstPortBucket
	if portBucket == "" {
		portBucket = "none"
	}
	vector := k.Vector
	if vector == "" {
		vector = SignalType("unknown")
	}
	return fmt.Sprintf("protocol=%s|dst_port_bucket=%s|vector=%s", protocol, portBucket, vector)
}

func campaignBaselineKey(vector SignalType, events []campaignSignal) CampaignBaselineKey {
	protocolCounts := make(map[string]int)
	portCounts := make(map[uint32]int)
	for _, ev := range events {
		protocol := serviceProtocol(ev.signal)
		protocolCounts[protocol]++
		if ev.dstPort > 0 {
			portCounts[ev.dstPort]++
		}
	}

	return CampaignBaselineKey{
		Protocol:      mostCommonString(protocolCounts, "unknown"),
		DstPortBucket: portBucket(mostCommonPort(portCounts)),
		Vector:        vector,
	}
}

func serviceProtocol(signal Signal) string {
	switch signal.Source {
	case SourceUDP:
		return "udp"
	case SourceTCP, SourceSPOE, SourceFingerprint:
		return "tcp"
	case SourceICMP:
		return "icmp"
	}
	transport := transportProtocol(signal.Metadata)
	if transport == "17" {
		return "udp"
	}
	if transport == "6" {
		return "tcp"
	}
	if transport != "" {
		return strings.ToLower(transport)
	}
	return "unknown"
}

func portBucket(port uint32) string {
	switch {
	case port == 0:
		return "none"
	case port <= 1024:
		return fmt.Sprintf("%d", port)
	case port == 1900 || port == 11211:
		return fmt.Sprintf("%d", port)
	case port < 10000:
		return "1025-9999"
	default:
		return "10000+"
	}
}

func mostCommonString(counts map[string]int, fallback string) string {
	best := fallback
	bestCount := 0
	for value, count := range counts {
		if count > bestCount || (count == bestCount && value < best) {
			best = value
			bestCount = count
		}
	}
	return best
}

func mostCommonPort(counts map[uint32]int) uint32 {
	var best uint32
	bestCount := 0
	for value, count := range counts {
		if count > bestCount || (count == bestCount && (best == 0 || value < best)) {
			best = value
			bestCount = count
		}
	}
	return best
}
