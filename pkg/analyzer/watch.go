package analyzer

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/aidetection"
	"PacketYeeter/pkg/metrics"
)

const (
	defaultWatchBufferSize     = 10000
	defaultWatchMaxSubscribers = 16

	watchKindCommand     = "command"
	watchKindCampaign    = "campaign"
	watchKindFingerprint = "fingerprint"

	// Generous upper bound on a collector's fingerprint interval; anything
	// larger is a malformed or hostile signal, not a configuration choice.
	maxFingerprintIntervalSeconds = 3600
	maxWatchSubscriberNameLen     = 64
)

func init() {
	// Export every kind from the start so dashboards see zeros, not gaps.
	for _, kind := range []string{watchKindCommand, watchKindCampaign, watchKindFingerprint} {
		metrics.WatchPublishedTotal.WithLabelValues(kind)
	}
}

// watchHub fans decisions out to WatchDecisions subscribers. Publishing only
// takes short locks and never waits on a subscriber, so a slow controller can
// never stall signal processing or command delivery to collectors.
type watchHub struct {
	maxSubscribers int
	bufferSize     int

	// mu serialises publishers so every subscriber sees the same order.
	mu     sync.Mutex
	subs   map[*watchSubscriber]struct{}
	active atomic.Int32
}

func newWatchHub(maxSubscribers, bufferSize int) *watchHub {
	if maxSubscribers <= 0 {
		maxSubscribers = defaultWatchMaxSubscribers
	}
	if bufferSize <= 0 {
		bufferSize = defaultWatchBufferSize
	}
	return &watchHub{
		maxSubscribers: maxSubscribers,
		bufferSize:     bufferSize,
		subs:           make(map[*watchSubscriber]struct{}),
	}
}

func (h *watchHub) subscribe(name string) (*watchSubscriber, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= h.maxSubscribers {
		return nil, false
	}
	s := &watchSubscriber{
		name:   name,
		ring:   make([]*apiv1.Decision, h.bufferSize),
		notify: make(chan struct{}, 1),
	}
	h.subs[s] = struct{}{}
	h.active.Store(int32(len(h.subs)))
	metrics.WatchSubscribers.Set(float64(len(h.subs)))
	return s, true
}

func (h *watchHub) unsubscribe(s *watchSubscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[s]; !ok {
		return
	}
	delete(h.subs, s)
	h.active.Store(int32(len(h.subs)))
	metrics.WatchSubscribers.Set(float64(len(h.subs)))
}

func (h *watchHub) publish(kind string, d *apiv1.Decision) {
	if h == nil {
		return
	}
	metrics.WatchPublishedTotal.WithLabelValues(kind).Inc()
	if h.active.Load() == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		s.push(d)
	}
}

// watchSubscriber is a fixed-size ring: when full, the oldest decision is
// overwritten so a controller that falls behind sees the most recent state.
type watchSubscriber struct {
	name   string
	notify chan struct{}

	mu      sync.Mutex
	ring    []*apiv1.Decision
	head    int
	n       int
	dropped uint64
}

func (s *watchSubscriber) push(d *apiv1.Decision) {
	s.mu.Lock()
	if s.n == len(s.ring) {
		s.ring[s.head] = nil
		s.head = (s.head + 1) % len(s.ring)
		s.n--
		s.dropped++
		metrics.WatchDroppedTotal.Inc()
	}
	s.ring[(s.head+s.n)%len(s.ring)] = d
	s.n++
	s.mu.Unlock()

	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *watchSubscriber) pop() *apiv1.Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == 0 {
		return nil
	}
	d := s.ring[s.head]
	s.ring[s.head] = nil
	s.head = (s.head + 1) % len(s.ring)
	s.n--
	return d
}

func (s *watchSubscriber) droppedCount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// WatchDecisions streams commands, campaign observations and scrub
// fingerprints to a controller. The handler goroutine is the subscriber's
// only sender, so there is nothing to leak once it returns.
func (a *Analyzer) WatchDecisions(req *apiv1.WatchRequest, stream apiv1.AnalyzerService_WatchDecisionsServer) error {
	if a.watch == nil {
		return status.Error(codes.PermissionDenied, "WatchDecisions is disabled; start the analyzer with -enable-watch-api")
	}
	name := watchSubscriberName(req.GetSubscriber())
	sub, ok := a.watch.subscribe(name)
	if !ok {
		logrus.WithFields(logrus.Fields{
			"subscriber":      name,
			"max_subscribers": a.watch.maxSubscribers,
		}).Warn("Refusing WatchDecisions subscriber: limit reached")
		return status.Error(codes.ResourceExhausted, "analyzer at WatchDecisions subscriber capacity")
	}
	defer a.watch.unsubscribe(sub)

	ctx := stream.Context()
	addr := "unknown"
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		addr = p.Addr.String()
	}
	log := logrus.WithFields(logrus.Fields{"subscriber": name, "peer": addr})
	log.Info("WatchDecisions subscriber connected")
	defer func() {
		log.WithField("dropped", sub.droppedCount()).Info("WatchDecisions subscriber disconnected")
	}()

	for {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-a.ctx.Done():
			return status.Error(codes.Unavailable, "analyzer shutting down")
		case <-sub.notify:
		}
		for d := sub.pop(); d != nil; d = sub.pop() {
			if err := stream.Send(d); err != nil {
				return err
			}
			if a.ctx.Err() != nil {
				return status.Error(codes.Unavailable, "analyzer shutting down")
			}
		}
	}
}

func watchSubscriberName(name string) string {
	if name == "" {
		return "unnamed"
	}
	if len(name) > maxWatchSubscriberNameLen {
		name = name[:maxWatchSubscriberNameLen]
	}
	return strings.ToValidUTF8(name, "?")
}

// publishCommand is the single hook for commands leaving the analyzer. Call it
// once per decision, after every gate (dry-run, kill switch, dedup) has
// passed, never once per collector.
func (a *Analyzer) publishCommand(cmd *apiv1.Command) {
	if a.watch == nil || cmd == nil {
		return
	}
	a.watch.publish(watchKindCommand, &apiv1.Decision{Kind: &apiv1.Decision_Command{Command: cmd}})
}

func (a *Analyzer) publishCampaign(d aidetection.CampaignDetection) {
	if a.watch == nil {
		return
	}
	a.watch.publish(watchKindCampaign, &apiv1.Decision{Kind: &apiv1.Decision_Campaign{Campaign: campaignObservation(d)}})
}

// campaignObservation maps the engine's detection onto the wire message.
// protocol is 0 and dst_port_bucket "" until the campaign baseline has been
// observed; dst_prefix is "" for cross-subnet rollups; rate_pps is the
// campaign's signal rate over the window, not a packet rate.
func campaignObservation(d aidetection.CampaignDetection) *apiv1.CampaignObservation {
	obs := &apiv1.CampaignObservation{
		Vector:        string(d.Vector),
		Protocol:      ipProtocolNumber(d.Baseline.Protocol),
		DstPortBucket: d.Baseline.DstPortBucket,
		DstPrefix:     d.DstPrefix(),
		RatePps:       d.Baseline.CurrentRate,
	}
	if !d.LastSeen.IsZero() {
		obs.ObservedAt = timestamppb.New(d.LastSeen)
	}
	return obs
}

func ipProtocolNumber(name string) uint32 {
	switch name {
	case "icmp":
		return 1
	case "tcp":
		return 6
	case "udp":
		return 17
	}
	if n, err := strconv.ParseUint(name, 10, 8); err == nil {
		return uint32(n)
	}
	return 0
}

// handleFingerprintSignal passes a scrub fingerprint through to subscribers.
// Fingerprints describe traffic towards a destination, not a client, so they
// must never reach scoring or reputation. collector_id is client-supplied and
// always replaced with the analyzer's own id for the stream.
func (a *Analyzer) handleFingerprintSignal(collectorID string, sig *apiv1.Signal) {
	fp := sig.GetFingerprint()
	if reason := invalidFingerprint(fp); reason != "" {
		metrics.WatchInvalidFingerprintsTotal.Inc()
		logrus.WithFields(logrus.Fields{
			"collector": collectorID,
			"reason":    reason,
		}).Debug("Dropping invalid scrub fingerprint")
		return
	}
	if a.watch == nil {
		return
	}
	fp.CollectorId = collectorID
	a.watch.publish(watchKindFingerprint, &apiv1.Decision{Kind: &apiv1.Decision_Fingerprint{Fingerprint: fp}})
}

func invalidFingerprint(fp *apiv1.ScrubFingerprint) string {
	switch {
	case fp == nil:
		return "missing fingerprint"
	case len(fp.DstIp) != 4 && len(fp.DstIp) != 16:
		return "dst_ip length"
	case len(fp.SrcNet) != len(fp.DstIp):
		return "src_net length"
	case fp.Protocol > 255:
		return "protocol out of range"
	case fp.DstPort > 65535:
		return "dst_port out of range"
	case fp.SizeBucket > 4:
		return "size_bucket out of range"
	case fp.TtlBucket > 7:
		return "ttl_bucket out of range"
	case fp.IntervalSeconds == 0 || fp.IntervalSeconds > maxFingerprintIntervalSeconds:
		return "interval_seconds out of range"
	}
	return ""
}
