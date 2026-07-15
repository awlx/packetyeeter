package aidetection

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultCampaignWindow              = 30 * time.Second
	defaultCampaignRetention           = 2 * time.Minute
	defaultCampaignMinSignals          = 20
	defaultCampaignMinDestIPs          = 16
	defaultCampaignMinDestSubnets      = 4
	defaultCampaignMinDestPorts        = 8
	defaultCampaignMinWeakSourceIPs    = 20
	defaultCampaignWeakSourceMaxWeight = 5.0
	defaultCampaignWeakSignalMaxWeight = 2.0
	defaultCampaignMaxCampaigns        = 4096
	defaultCampaignMaxEvents           = 4096
)

type CampaignConfig struct {
	Window              time.Duration
	Retention           time.Duration
	MinSignals          int
	MinDestIPs          int
	MinDestSubnets      int
	MinDestPorts        int
	MinWeakSourceIPs    int
	WeakSourceMaxWeight float64
	WeakSignalMaxWeight float64
	MaxCampaigns        int
	MaxEvents           int
	Baseline            CampaignBaselineConfig
}

func DefaultCampaignConfig() CampaignConfig {
	return CampaignConfig{
		Window:              defaultCampaignWindow,
		Retention:           defaultCampaignRetention,
		MinSignals:          defaultCampaignMinSignals,
		MinDestIPs:          defaultCampaignMinDestIPs,
		MinDestSubnets:      defaultCampaignMinDestSubnets,
		MinDestPorts:        defaultCampaignMinDestPorts,
		MinWeakSourceIPs:    defaultCampaignMinWeakSourceIPs,
		WeakSourceMaxWeight: defaultCampaignWeakSourceMaxWeight,
		WeakSignalMaxWeight: defaultCampaignWeakSignalMaxWeight,
		MaxCampaigns:        defaultCampaignMaxCampaigns,
		MaxEvents:           defaultCampaignMaxEvents,
		Baseline:            DefaultCampaignBaselineConfig(),
	}
}

func normalizeCampaignConfig(cfg CampaignConfig) CampaignConfig {
	def := DefaultCampaignConfig()
	if cfg.Window == 0 {
		cfg.Window = def.Window
	}
	if cfg.Retention == 0 {
		cfg.Retention = def.Retention
	}
	if cfg.MinSignals == 0 {
		cfg.MinSignals = def.MinSignals
	}
	if cfg.MinDestIPs == 0 {
		cfg.MinDestIPs = def.MinDestIPs
	}
	if cfg.MinDestSubnets == 0 {
		cfg.MinDestSubnets = def.MinDestSubnets
	}
	if cfg.MinDestPorts == 0 {
		cfg.MinDestPorts = def.MinDestPorts
	}
	if cfg.MinWeakSourceIPs == 0 {
		cfg.MinWeakSourceIPs = def.MinWeakSourceIPs
	}
	if cfg.WeakSourceMaxWeight == 0 {
		cfg.WeakSourceMaxWeight = def.WeakSourceMaxWeight
	}
	if cfg.WeakSignalMaxWeight == 0 {
		cfg.WeakSignalMaxWeight = def.WeakSignalMaxWeight
	}
	if cfg.MaxCampaigns == 0 {
		cfg.MaxCampaigns = def.MaxCampaigns
	}
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = def.MaxEvents
	}
	cfg.Baseline = normalizeCampaignBaselineConfig(cfg.Baseline)
	return cfg
}

type CampaignDetection struct {
	ID               string
	Key              string
	Vector           SignalType
	Reason           string
	FirstSeen        time.Time
	LastSeen         time.Time
	SignalCount      int
	TotalWeight      float64
	DestinationIPs   int
	DestSubnets      int
	DestinationPorts int
	SourceIPs        int
	ASNs             int
	Collectors       int
	SourceKinds      int
	SampleIP         net.IP
	SampleDestIP     string
	SampleDstPort    uint32
	SampleASN        string
	SampleOrg        string
	Baseline         CampaignBaselineObservation
}

type campaignSignal struct {
	signalType SignalType
	source     SignalSource
	ip         net.IP
	asn        string
	org        string
	weight     float64
	timestamp  time.Time
	protocol   string
	destIP     string
	destSubnet string
	dstPort    uint32
	collector  string
}

type attackCampaign struct {
	key           string
	vector        SignalType
	firstSeen     time.Time
	lastSeen      time.Time
	events        []campaignSignal
	lastDetection time.Time
	lastReason    string
}

type CampaignAggregator struct {
	mu        sync.Mutex
	cfg       CampaignConfig
	campaigns map[string]*attackCampaign
	baseline  *CampaignBaselineTracker
}

func NewCampaignAggregator(cfg CampaignConfig) *CampaignAggregator {
	cfg = normalizeCampaignConfig(cfg)
	return &CampaignAggregator{
		cfg:       cfg,
		campaigns: make(map[string]*attackCampaign),
		baseline:  NewCampaignBaselineTracker(cfg.Baseline),
	}
}

func (a *CampaignAggregator) Record(signal Signal) {
	if a == nil {
		return
	}
	if signal.Timestamp.IsZero() {
		signal.Timestamp = time.Now()
	}
	destIP, destSubnet := destinationIdentity(signal.Metadata)
	dstPort := destinationPort(signal.Metadata)
	collector := metadataString(signal.Metadata, "collector_id", "collector", "source_collector")
	if collector == "" {
		collector = "unknown"
	}
	campaignSignal := signal
	campaignSignal.Type = classifyUDPAttackVector(signal)

	// Every signal contributes to exactly three campaign buckets:
	//  1. the specific-subnet campaign (vector+source+collector+destSubnet), which
	//     tracks fine-grained breadth (destination IPs/ports, weak sources) for one
	//     collector/subnet pair.
	//  2. a per-collector cross-subnet aggregate ("dest_subnet=any") used to catch
	//     carpet-bombing that spreads across many destination subnets behind a
	//     single collector without inflating any one subnet's counters.
	//  3. a fully global aggregate ("collector=any|dest_subnet=any") used to catch
	//     carpet-bombing that also spreads across collectors, so an attacker can't
	//     evade aggregation by varying collector_id alone.
	// Each of these is a genuinely distinct rollup key (a separate campaign entry),
	// not a duplicate copy of the same totals - evaluateCampaignLocked further
	// guards the aggregate levels so they only ever report a detection when they
	// represent breadth that the narrower scope beneath them does not already
	// capture (see the distinctRollup check), preventing double-counted
	// detections/baseline samples for the same underlying signal.
	key := campaignKey(campaignSignal.Type, campaignSignal.Source, collector, destSubnet)
	subnetAggKey := campaignKey(campaignSignal.Type, campaignSignal.Source, collector, "any")
	globalAggKey := campaignKey(campaignSignal.Type, campaignSignal.Source, "any", "any")

	a.mu.Lock()
	defer a.mu.Unlock()

	a.recordLocked(key, campaignSignal, destIP, destSubnet, dstPort, collector)
	if subnetAggKey != key {
		a.recordLocked(subnetAggKey, campaignSignal, destIP, destSubnet, dstPort, collector)
	}
	if globalAggKey != subnetAggKey {
		a.recordLocked(globalAggKey, campaignSignal, destIP, destSubnet, dstPort, collector)
	}
}

func (a *CampaignAggregator) recordLocked(key string, signal Signal, destIP, destSubnet string, dstPort uint32, collector string) {
	c := a.campaigns[key]
	if c == nil {
		if len(a.campaigns) >= a.cfg.MaxCampaigns {
			return
		}
		c = &attackCampaign{
			key:       key,
			vector:    signal.Type,
			firstSeen: signal.Timestamp,
		}
		a.campaigns[key] = c
	}
	if c.firstSeen.IsZero() || signal.Timestamp.Before(c.firstSeen) {
		c.firstSeen = signal.Timestamp
	}
	if signal.Timestamp.After(c.lastSeen) {
		c.lastSeen = signal.Timestamp
	}
	c.events = append(c.events, campaignSignal{
		signalType: signal.Type,
		source:     signal.Source,
		ip:         append(net.IP(nil), signal.IP...),
		asn:        signal.ASN,
		org:        signal.Org,
		weight:     signal.Weight,
		timestamp:  signal.Timestamp,
		protocol:   serviceProtocol(signal),
		destIP:     destIP,
		destSubnet: destSubnet,
		dstPort:    dstPort,
		collector:  collector,
	})
	a.pruneCampaignLocked(c, signal.Timestamp)
	if excess := len(c.events) - a.cfg.MaxEvents; excess > 0 {
		copy(c.events, c.events[excess:])
		c.events = c.events[:a.cfg.MaxEvents]
	}
}

func (a *CampaignAggregator) Evaluate(now time.Time) []CampaignDetection {
	if a == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	detections := make([]CampaignDetection, 0)
	for key, c := range a.campaigns {
		a.pruneCampaignLocked(c, now)
		if len(c.events) == 0 || now.Sub(c.lastSeen) > a.cfg.Retention {
			delete(a.campaigns, key)
			continue
		}

		detection, ok := a.evaluateCampaignLocked(c)
		if !ok {
			continue
		}
		baseline := a.observeBaselineLocked(c, now)
		detection.Baseline = baseline
		if c.lastReason == detection.Reason && !c.lastDetection.IsZero() && now.Sub(c.lastDetection) < a.cfg.Window {
			continue
		}
		c.lastReason = detection.Reason
		c.lastDetection = now
		detections = append(detections, detection)
	}
	return detections
}

func (a *CampaignAggregator) observeBaselineLocked(c *attackCampaign, now time.Time) CampaignBaselineObservation {
	if c == nil || len(c.events) == 0 || a.baseline == nil {
		return CampaignBaselineObservation{}
	}
	windowSeconds := a.cfg.Window.Seconds()
	if windowSeconds <= 0 {
		windowSeconds = 1
	}
	key := campaignBaselineKey(c.vector, c.events, campaignScope(c.key))
	return a.baseline.Observe(key, float64(len(c.events))/windowSeconds, now)
}

// campaignScope classifies a campaign key as the fine-grained "specific"
// campaign, the per-collector cross-subnet "subnet_aggregate" rollup, or the
// fully cross-collector "global_aggregate" rollup. It is folded into the
// baseline key so that samples from these genuinely different scopes never
// share (and inflate) the same adaptive baseline/multiplier state.
func campaignScope(key string) string {
	anySubnet := strings.Contains(key, "dest_subnet=any")
	anyCollector := strings.Contains(key, "collector=any")
	switch {
	case anySubnet && anyCollector:
		return "global_aggregate"
	case anySubnet:
		return "subnet_aggregate"
	default:
		return "specific"
	}
}

func (a *CampaignAggregator) ActiveCampaigns(now time.Time) int {
	if a == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now()
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	active := 0
	for key, c := range a.campaigns {
		a.pruneCampaignLocked(c, now)
		if len(c.events) == 0 || now.Sub(c.lastSeen) > a.cfg.Retention {
			delete(a.campaigns, key)
			continue
		}
		active++
	}
	return active
}

func (a *CampaignAggregator) pruneCampaignLocked(c *attackCampaign, now time.Time) {
	cutoff := now.Add(-a.cfg.Window)
	kept := c.events[:0]
	for _, ev := range c.events {
		if !ev.timestamp.Before(cutoff) {
			kept = append(kept, ev)
		}
	}
	c.events = kept
	if len(c.events) == 0 {
		return
	}
	c.firstSeen = c.events[0].timestamp
	c.lastSeen = c.events[0].timestamp
	for _, ev := range c.events[1:] {
		if ev.timestamp.Before(c.firstSeen) {
			c.firstSeen = ev.timestamp
		}
		if ev.timestamp.After(c.lastSeen) {
			c.lastSeen = ev.timestamp
		}
	}
}

func (a *CampaignAggregator) evaluateCampaignLocked(c *attackCampaign) (CampaignDetection, bool) {
	if len(c.events) < a.cfg.MinSignals {
		return CampaignDetection{}, false
	}

	destIPs := make(map[string]struct{})
	destSubnets := make(map[string]struct{})
	destPorts := make(map[uint32]struct{})
	sourceIPs := make(map[string]struct{})
	sourceWeights := make(map[string]float64)
	asns := make(map[string]struct{})
	collectors := make(map[string]struct{})
	sourceKinds := make(map[SignalSource]struct{})
	totalWeight := 0.0

	var sampleIP net.IP
	var sampleDestIP string
	var sampleDstPort uint32
	var sampleASN, sampleOrg string

	for _, ev := range c.events {
		w := ev.weight
		if w == 0 {
			w = 1
		}
		totalWeight += w
		if ev.destIP != "" {
			destIPs[ev.destIP] = struct{}{}
			if sampleDestIP == "" {
				sampleDestIP = ev.destIP
			}
		}
		if ev.destSubnet != "" && ev.destSubnet != "unknown" {
			destSubnets[ev.destSubnet] = struct{}{}
		}
		if ev.dstPort > 0 {
			destPorts[ev.dstPort] = struct{}{}
			if sampleDstPort == 0 {
				sampleDstPort = ev.dstPort
			}
		}
		if ev.ip != nil {
			ip := ev.ip.String()
			sourceIPs[ip] = struct{}{}
			sourceWeights[ip] += w
			if sampleIP == nil {
				sampleIP = append(net.IP(nil), ev.ip...)
			}
		}
		if ev.asn != "" && ev.asn != "Unknown" {
			asns[ev.asn] = struct{}{}
			if sampleASN == "" {
				sampleASN = ev.asn
			}
		}
		if ev.org != "" && sampleOrg == "" {
			sampleOrg = ev.org
		}
		if ev.collector != "" {
			collectors[ev.collector] = struct{}{}
		}
		sourceKinds[ev.source] = struct{}{}
	}

	// aggregateSubnetKey identifies either of the two cross-subnet rollups
	// (per-collector "dest_subnet=any" and the fully global "collector=any|
	// dest_subnet=any"). aggregateCollectorKey narrows that further to the
	// fully global rollup.
	aggregateSubnetKey := strings.Contains(c.key, "dest_subnet=any")
	aggregateCollectorKey := strings.Contains(c.key, "collector=any")

	if aggregateSubnetKey {
		// A per-collector cross-subnet rollup only adds information beyond a
		// single specific-subnet campaign when it genuinely spans more than
		// one destination subnet. The fully global (cross-collector) rollup
		// only adds information beyond the per-collector rollup when it
		// genuinely spans more than one collector - otherwise, with a single
		// collector in play, it is just a duplicate copy of that collector's
		// subnet-aggregate campaign and must not be allowed to double-count
		// detections or baseline samples for the same underlying signal.
		var distinctRollup bool
		if aggregateCollectorKey {
			distinctRollup = len(collectors) > 1
		} else {
			distinctRollup = len(destSubnets) > 1
		}
		if !distinctRollup {
			return CampaignDetection{}, false
		}
	}

	destSubnetBreadth := len(destSubnets) >= a.cfg.MinDestSubnets
	destIPBreadth := !aggregateSubnetKey && len(destIPs) >= a.cfg.MinDestIPs
	destPortBreadth := !aggregateSubnetKey && len(destPorts) >= a.cfg.MinDestPorts
	// Weak-source breadth is evaluated independently of the destination-breadth
	// checks above (not gated behind them failing), so an attacker who spreads
	// across many weak source IPs *and* many destination subnets/collectors at
	// once is still caught - either individually or via the aggregate rollups -
	// instead of evading detection by keeping every single check just under its
	// own threshold.
	weakSourceBreadth := len(sourceIPs) >= a.cfg.MinWeakSourceIPs &&
		weakSourceWeights(sourceWeights, a.cfg.WeakSourceMaxWeight) &&
		averageWeight(totalWeight, len(c.events)) <= a.cfg.WeakSignalMaxWeight

	reason := ""
	switch {
	case destSubnetBreadth:
		reason = "destination_subnet_breadth"
	case destIPBreadth:
		reason = "destination_ip_breadth"
	case destPortBreadth:
		reason = "destination_port_breadth"
	case weakSourceBreadth:
		reason = "weak_source_breadth"
	}
	if reason == "" {
		return CampaignDetection{}, false
	}

	return CampaignDetection{
		ID:               stableCampaignID(c.key, c.firstSeen),
		Key:              c.key,
		Vector:           c.vector,
		Reason:           reason,
		FirstSeen:        c.firstSeen,
		LastSeen:         c.lastSeen,
		SignalCount:      len(c.events),
		TotalWeight:      totalWeight,
		DestinationIPs:   len(destIPs),
		DestSubnets:      len(destSubnets),
		DestinationPorts: len(destPorts),
		SourceIPs:        len(sourceIPs),
		ASNs:             len(asns),
		Collectors:       len(collectors),
		SourceKinds:      len(sourceKinds),
		SampleIP:         sampleIP,
		SampleDestIP:     sampleDestIP,
		SampleDstPort:    sampleDstPort,
		SampleASN:        sampleASN,
		SampleOrg:        sampleOrg,
	}, true
}

// campaignRuleConfidence derives a rule-based confidence score for a campaign
// detection from the evidence that actually triggered it (signal volume,
// breadth relative to the configured thresholds, source/collector/vector
// diversity, and adaptive-baseline corroboration) instead of a fixed magic
// constant. It mirrors the spirit of CalculateConfidence but is built from
// campaign-level aggregates since no single per-signal confidence exists at
// this aggregation level. The result is meant to be fed into
// blendMLConfidence alongside a representative ML prediction, exactly like
// the non-campaign detection path in handleDetection.
func campaignRuleConfidence(detection CampaignDetection, cfg CampaignConfig) float64 {
	confidence := 0.5

	if cfg.MinSignals > 0 {
		volumeExcess := math.Max(0, float64(detection.SignalCount)/float64(cfg.MinSignals)-1)
		confidence += math.Min(volumeExcess/10.0, 0.15)
	}

	breadthExcess := make([]float64, 0, 4)
	if cfg.MinDestIPs > 0 && detection.DestinationIPs > 0 {
		breadthExcess = append(breadthExcess, float64(detection.DestinationIPs)/float64(cfg.MinDestIPs)-1)
	}
	if cfg.MinDestSubnets > 0 && detection.DestSubnets > 0 {
		breadthExcess = append(breadthExcess, float64(detection.DestSubnets)/float64(cfg.MinDestSubnets)-1)
	}
	if cfg.MinDestPorts > 0 && detection.DestinationPorts > 0 {
		breadthExcess = append(breadthExcess, float64(detection.DestinationPorts)/float64(cfg.MinDestPorts)-1)
	}
	if cfg.MinWeakSourceIPs > 0 && detection.SourceIPs > 0 {
		breadthExcess = append(breadthExcess, float64(detection.SourceIPs)/float64(cfg.MinWeakSourceIPs)-1)
	}
	maxExcess := 0.0
	for _, r := range breadthExcess {
		if r > maxExcess {
			maxExcess = r
		}
	}
	if maxExcess > 0 {
		confidence += math.Min(maxExcess/10.0, 0.2)
	}

	diversity := detection.ASNs + detection.Collectors + detection.SourceKinds
	confidence += math.Min(float64(diversity)/10.0, 0.1)

	if detection.Baseline.EnoughSamples && detection.Baseline.Anomalous {
		confidence += math.Min(detection.Baseline.Multiplier/20.0, 0.2)
	}

	return clampConfidence(confidence)
}

// campaignSeverityMultiplier scales reputation penalties for a campaign
// detection with how far it exceeds the configured breadth thresholds, so
// larger/broader campaigns (and repeated campaign involvement) accumulate
// proportionally larger reputation penalties over time. It is capped to keep
// a single detection cycle from applying an unbounded penalty even for very
// large carpet-bombing campaigns.
func campaignSeverityMultiplier(detection CampaignDetection, cfg CampaignConfig) float64 {
	const maxMultiplier = 5.0
	multiplier := 1.0

	if cfg.MinSignals > 0 {
		multiplier = math.Max(multiplier, float64(detection.SignalCount)/float64(cfg.MinSignals))
	}
	if cfg.MinDestIPs > 0 && detection.DestinationIPs > 0 {
		multiplier = math.Max(multiplier, float64(detection.DestinationIPs)/float64(cfg.MinDestIPs))
	}
	if cfg.MinDestSubnets > 0 && detection.DestSubnets > 0 {
		multiplier = math.Max(multiplier, float64(detection.DestSubnets)/float64(cfg.MinDestSubnets))
	}
	if cfg.MinWeakSourceIPs > 0 && detection.SourceIPs > 0 {
		multiplier = math.Max(multiplier, float64(detection.SourceIPs)/float64(cfg.MinWeakSourceIPs))
	}
	if detection.Baseline.EnoughSamples && detection.Baseline.Anomalous && detection.Baseline.Multiplier > 1 {
		multiplier = math.Max(multiplier, detection.Baseline.Multiplier/3.0)
	}

	if multiplier > maxMultiplier {
		multiplier = maxMultiplier
	}
	return multiplier
}

func campaignKey(vector SignalType, source SignalSource, collector, destSubnet string) string {
	if destSubnet == "" {
		destSubnet = "unknown"
	}
	return fmt.Sprintf("vector=%s|source=%s|collector=%s|dest_subnet=%s", vector, source, collector, destSubnet)
}

func stableCampaignID(key string, firstSeen time.Time) string {
	return fmt.Sprintf("%x", fnv64(key+"|"+firstSeen.UTC().Format(time.RFC3339Nano)))
}

func fnv64(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}

func weakSourceWeights(weights map[string]float64, maxWeight float64) bool {
	if len(weights) == 0 {
		return false
	}
	for _, w := range weights {
		if w > maxWeight {
			return false
		}
	}
	return true
}

func averageWeight(total float64, count int) float64 {
	if count == 0 {
		return 0
	}
	return total / float64(count)
}

func destinationIdentity(metadata map[string]interface{}) (string, string) {
	raw := metadataString(metadata, "dest_ip", "dst_ip", "destination_ip")
	if raw == "" {
		return "", "unknown"
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", "unknown"
	}
	return ip.String(), subnetForIP(ip)
}

func subnetForIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return (&net.IPNet{IP: net.IPv4(ip4[0], ip4[1], ip4[2], 0), Mask: net.CIDRMask(24, 32)}).String()
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return "unknown"
	}
	subnetIP := make(net.IP, len(ip16))
	copy(subnetIP, ip16)
	for i := 8; i < len(subnetIP); i++ {
		subnetIP[i] = 0
	}
	return (&net.IPNet{IP: subnetIP, Mask: net.CIDRMask(64, 128)}).String()
}

func destinationPort(metadata map[string]interface{}) uint32 {
	if metadata == nil {
		return 0
	}
	for _, key := range []string{"dst_port", "dest_port", "destination_port"} {
		if v, ok := metadata[key]; ok {
			if port, ok := uint32FromValue(v); ok {
				return port
			}
		}
	}
	return 0
}

func metadataString(metadata map[string]interface{}, keys ...string) string {
	if metadata == nil {
		return ""
	}
	for _, key := range keys {
		if v, ok := metadata[key]; ok {
			switch typed := v.(type) {
			case string:
				return typed
			case fmt.Stringer:
				return typed.String()
			case net.IP:
				return typed.String()
			}
		}
	}
	return ""
}

func uint32FromValue(v interface{}) (uint32, bool) {
	switch typed := v.(type) {
	case uint32:
		return typed, typed > 0
	case uint16:
		return uint32(typed), typed > 0
	case int:
		return uint32(typed), typed > 0
	case int64:
		return uint32(typed), typed > 0
	case float64:
		return uint32(typed), typed > 0
	case string:
		port, err := strconv.ParseUint(typed, 10, 32)
		if err == nil && port > 0 {
			return uint32(port), true
		}
	}
	return 0, false
}
