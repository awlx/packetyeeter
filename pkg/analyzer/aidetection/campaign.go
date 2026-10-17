package aidetection

import (
	"fmt"
	"math"
	"net"
	"net/netip"
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
	key       string
	vector    SignalType
	firstSeen time.Time
	lastSeen  time.Time
	events    campaignEvents
	// episode uniquely identifies this campaign instance. It is assigned once
	// when the campaign is first created and never changes while the campaign
	// lives, so the derived campaign_id is stable within an episode. When a
	// campaign fully ages out (deleted from the map) and a later burst on the
	// same key creates a new attackCampaign, that instance gets a new episode
	// and therefore a distinct campaign_id - two unrelated episodes are not
	// conflated under one id.
	episode             uint64
	lastDetection       time.Time
	lastReason          string
	lastBaseline        CampaignBaselineObservation
	lastBaselineObserve time.Time
}

type CampaignAggregator struct {
	mu         sync.Mutex
	cfg        CampaignConfig
	campaigns  map[string]*attackCampaign
	baseline   *CampaignBaselineTracker
	episodeSeq uint64
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
	classified := signal
	classified.Type = classifyUDPAttackVector(signal)

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
	key := campaignKey(classified.Type, classified.Source, collector, destSubnet)
	subnetAggKey := campaignKey(classified.Type, classified.Source, collector, "any")
	globalAggKey := campaignKey(classified.Type, classified.Source, "any", "any")

	event := campaignSignal{
		signalType: classified.Type,
		source:     classified.Source,
		ip:         append(net.IP(nil), classified.IP...),
		asn:        classified.ASN,
		org:        classified.Org,
		weight:     classified.Weight,
		timestamp:  classified.Timestamp,
		protocol:   serviceProtocol(classified),
		destIP:     destIP,
		destSubnet: destSubnet,
		dstPort:    dstPort,
		collector:  collector,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.recordLocked(key, event)
	if subnetAggKey != key {
		a.recordLocked(subnetAggKey, event)
	}
	if globalAggKey != subnetAggKey {
		a.recordLocked(globalAggKey, event)
	}
}

func (a *CampaignAggregator) recordLocked(key string, event campaignSignal) {
	c := a.campaigns[key]
	if c == nil {
		if len(a.campaigns) >= a.cfg.MaxCampaigns {
			return
		}
		a.episodeSeq++
		c = &attackCampaign{
			key:       key,
			vector:    event.signalType,
			firstSeen: event.timestamp,
			events:    newCampaignEvents(a.cfg.MaxEvents),
			episode:   a.episodeSeq,
		}
		a.campaigns[key] = c
	}
	if c.firstSeen.IsZero() || event.timestamp.Before(c.firstSeen) {
		c.firstSeen = event.timestamp
	}
	if event.timestamp.After(c.lastSeen) {
		c.lastSeen = event.timestamp
	}
	c.events.Push(event)
	a.pruneCampaignLocked(c, event.timestamp)
	c.events.TrimTo(a.cfg.MaxEvents)
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
		if c.events.Len() == 0 || now.Sub(c.lastSeen) > a.cfg.Retention {
			delete(a.campaigns, key)
			continue
		}

		detection, ok := a.evaluateCampaignLocked(c)
		if !ok {
			continue
		}
		// Feed the corroborating baseline at most once per Window per campaign,
		// REGARDLESS of the detection reason. Observing on every evaluation tick
		// fed a sustained campaign's own attack rate into the adaptive baseline,
		// training it up toward that rate until the campaign no longer read as
		// anomalous. The previous guard keyed on the reason as well, so a
		// campaign whose reason flapped (e.g. alternating destination_ip_breadth
		// / source_ip_breadth across ticks) slipped past it and retrained the
		// baseline every tick. Gate purely on elapsed time since the last
		// observation so reason flapping cannot self-poison the baseline.
		if c.lastBaselineObserve.IsZero() || now.Sub(c.lastBaselineObserve) >= a.cfg.Window {
			c.lastBaseline = a.observeBaselineLocked(c, now)
			c.lastBaselineObserve = now
		}
		detection.Baseline = c.lastBaseline

		// Detection emission dedup: suppress a repeat of the SAME reason within
		// the window (unchanged), but let a changed reason (or a new window)
		// through so operators still see it. This no longer affects baseline
		// training, which is handled above.
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
	if c == nil || c.events.Len() == 0 || a.baseline == nil {
		return CampaignBaselineObservation{}
	}
	windowSeconds := a.cfg.Window.Seconds()
	if windowSeconds <= 0 {
		windowSeconds = 1
	}
	key := campaignBaselineKey(c.vector, &c.events, campaignScope(c.key))
	return a.baseline.Observe(key, float64(c.events.Len())/windowSeconds, now)
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
		if c.events.Len() == 0 || now.Sub(c.lastSeen) > a.cfg.Retention {
			delete(a.campaigns, key)
			continue
		}
		if _, detected := a.evaluateCampaignLocked(c); detected {
			active++
		}
	}
	return active
}

func (a *CampaignAggregator) pruneCampaignLocked(c *attackCampaign, now time.Time) {
	cutoff := now.Add(-a.cfg.Window)
	if c.events.Len() == 0 || !c.firstSeen.Before(cutoff) {
		return
	}
	firstSeen, lastSeen, ok := c.events.PruneBefore(cutoff)
	if !ok {
		return
	}
	c.firstSeen = firstSeen
	c.lastSeen = lastSeen
}

func (a *CampaignAggregator) evaluateCampaignLocked(c *attackCampaign) (CampaignDetection, bool) {
	if c.events.Len() < a.cfg.MinSignals {
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

	for i := range c.events.Len() {
		ev := c.events.At(i)
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
		averageWeight(totalWeight, c.events.Len()) <= a.cfg.WeakSignalMaxWeight

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
		ID:               stableCampaignID(c.key, c.episode),
		Key:              c.key,
		Vector:           c.vector,
		Reason:           reason,
		FirstSeen:        c.firstSeen,
		LastSeen:         c.lastSeen,
		SignalCount:      c.events.Len(),
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

func campaignKey(vector SignalType, source SignalSource, collector, destSubnet string) string {
	if destSubnet == "" {
		destSubnet = "unknown"
	}
	return "vector=" + string(vector) + "|source=" + string(source) + "|collector=" + collector + "|dest_subnet=" + destSubnet
}

// DstPrefix returns the destination subnet a specific-scope campaign is keyed
// on, or "" for the cross-subnet rollups and signals without a destination.
func (d CampaignDetection) DstPrefix() string {
	const marker = "|dest_subnet="
	i := strings.LastIndex(d.Key, marker)
	if i < 0 {
		return ""
	}
	prefix := d.Key[i+len(marker):]
	if prefix == "any" || prefix == "unknown" {
		return ""
	}
	return prefix
}

// stableCampaignID derives an ID from the campaign's stable key AND its episode
// token. It must NOT incorporate firstSeen: pruneCampaignLocked slides firstSeen
// forward as old events age out of the window, so hashing it would mint a new ID
// every cycle for any campaign that outlives the window, breaking campaign_id
// correlation across a single continuous campaign. The episode token, by
// contrast, is fixed for the campaign's whole lifetime and only changes when a
// brand-new campaign instance is created on the same key after the previous one
// aged out - so the id is stable within an episode but distinct across episodes.
func stableCampaignID(key string, episode uint64) string {
	return fmt.Sprintf("%x", fnv64(fmt.Sprintf("%s|episode=%d", key, episode)))
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
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" {
		return "", "unknown"
	}
	addr = addr.Unmap()
	return addr.String(), subnetForAddr(addr)
}

func subnetForAddr(addr netip.Addr) string {
	bits := 64
	if addr.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(addr, bits).Masked().String()
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
