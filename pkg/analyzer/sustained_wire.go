package analyzer

import (
	"net"
	"sync"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/sustained"
	"PacketYeeter/pkg/metrics"

	"github.com/sirupsen/logrus"
)

// verifiedBotTTL bounds how long a successful bot verification keeps raising a
// client's sustained-download thresholds. It is deliberately shorter than the
// verifier's own cache: this grants a client more headroom, so it should lapse
// on its own rather than persist for as long as an identity lookup stays valid.
const verifiedBotTTL = 30 * time.Minute

// verifiedBotSet remembers which clients recently passed bot verification.
//
// The tracker needs a good-reputation signal it can consult synchronously
// during evaluation, and the reputation engine cannot supply one: entries there
// are only created by penalties, so a score of zero means "never seen" rather
// than "well behaved". Verified crawlers are the opposite - an affirmative,
// independently checked good standing, and the exact class that legitimately
// walks a lot of the namespace.
type verifiedBotSet struct {
	mu      sync.RWMutex
	entries map[string]time.Time
}

func newVerifiedBotSet() *verifiedBotSet {
	return &verifiedBotSet{entries: make(map[string]time.Time)}
}

func (s *verifiedBotSet) mark(ip string, now time.Time) {
	if ip == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[ip] = now
}

func (s *verifiedBotSet) contains(ip string, now time.Time) bool {
	s.mu.RLock()
	seen, ok := s.entries[ip]
	s.mu.RUnlock()
	return ok && now.Sub(seen) < verifiedBotTTL
}

// prune drops lapsed entries. Called from the evaluation loop so the set is
// bounded by the number of clients verified within the TTL rather than growing
// for the lifetime of the process.
func (s *verifiedBotSet) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, seen := range s.entries {
		if now.Sub(seen) >= verifiedBotTTL {
			delete(s.entries, ip)
		}
	}
}

// initSustained constructs the sustained-download tracker. It is a no-op when
// the feature is disabled, so every observation hook stays nil-safe.
func (a *Analyzer) initSustained() {
	if !a.Config.Sustained.Enabled {
		logrus.Debug("Sustained-download detection disabled")
		return
	}

	a.sustainedVerified = newVerifiedBotSet()
	a.Sustained = sustained.New(a.Config.Sustained,
		sustained.WithReputation(func(ip string) bool {
			return a.sustainedVerified.contains(ip, time.Now())
		}),
	)

	cfg := a.Sustained.Settings()
	logrus.WithFields(logrus.Fields{
		"enforce":           cfg.Enforce && !a.Config.DryRun,
		"window_seconds":    cfg.WindowSeconds,
		"minimum_requests":  cfg.MinimumRequests,
		"minimum_bytes":     cfg.MinimumBytes,
		"minimum_resources": cfg.MinimumResources,
		"minimum_sections":  cfg.MinimumSections,
		"maximum_clients":   cfg.MaximumClients,
	}).Info("Sustained-download detection initialized")

	if !cfg.Enforce {
		logrus.Info("Sustained-download detection is detect-only; decisions will be logged as would-block")
	}
}

// observeSustainedRequest feeds the shape/breadth side of the tracker from the
// SPOE HTTP path.
//
// Allowlisted clients are skipped outright rather than given raised thresholds.
// The allowlist is an explicit operator override used that way everywhere else
// in the analyzer, and a detection that ignored it would be a surprise in the
// one place surprises are most expensive.
func (a *Analyzer) observeSustainedRequest(ip net.IP, ctx *apiv1.HTTPContext) {
	if a.Sustained == nil || ip == nil || ctx == nil {
		return
	}
	client := ip.String()
	if a.AIEngine != nil && a.AIEngine.IsAllowlisted(client) {
		return
	}
	a.Sustained.ObserveRequest(client, ctx.Host, ctx.Path)
}

// markSustainedVerifiedBot records that a client passed bot verification, which
// raises its thresholds on the next evaluation.
func (a *Analyzer) markSustainedVerifiedBot(ip net.IP) {
	if a.sustainedVerified == nil || ip == nil {
		return
	}
	a.sustainedVerified.mark(ip.String(), time.Now())
}

// observeSustainedBytes feeds the volume side of the tracker from the collector's
// eBPF egress byte counters.
//
// These are real wire bytes. HAProxy cannot report transferred bytes over SPOE
// at all - its byte counters are stream-scoped and a fresh stream is allocated
// per keep-alive request - so the egress path is the only source that sees
// streamed and chunked responses.
func (a *Analyzer) observeSustainedBytes(sig *apiv1.Signal, ip net.IP) {
	if a.Sustained == nil || ip == nil || sig.EgressContext == nil {
		return
	}
	client := ip.String()
	if a.AIEngine != nil && a.AIEngine.IsAllowlisted(client) {
		return
	}
	a.Sustained.ObserveBytes(client, sig.EgressContext.BytesDelta)
}

// runSustainedEvaluator periodically evaluates the tracker and acts on its
// decisions.
func (a *Analyzer) runSustainedEvaluator() {
	defer a.wg.Done()

	// Tick at half the evaluation interval and let the tracker's own guard
	// decide when an evaluation is due. Ticking at exactly the interval would
	// race that guard: normal scheduling jitter puts a tick a few microseconds
	// early, the tracker declines it, and the effective interval silently
	// doubles.
	interval := time.Duration(a.Sustained.Settings().EvaluationIntervalSeconds) * time.Second / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.evaluateSustained()
		}
	}
}

func (a *Analyzer) evaluateSustained() {
	now := time.Now()
	if a.sustainedVerified != nil {
		a.sustainedVerified.prune(now)
	}

	decisions := a.Sustained.Evaluate()
	// Both gates apply: the detector's own -sustained-enforce, and the
	// analyzer-wide enforcement state (dry-run plus the runtime kill switch).
	enforcing := a.Sustained.Enforcing() && a.Enforcing()

	for _, decision := range decisions {
		a.actOnSustainedDecision(decision, enforcing)
	}

	stats := a.Sustained.Stats()
	metrics.SustainedTrackedClients.Set(float64(stats.TrackedClients))
	metrics.SustainedHeldClients.Set(float64(stats.HeldClients))

	// The tracker reports running totals; Prometheus counters take increments.
	// Only this goroutine touches these, so no synchronization is needed.
	if delta := stats.ClientEvictions - a.sustainedLastEvictions; delta > 0 {
		metrics.SustainedClientEvictions.Add(float64(delta))
		a.sustainedLastEvictions = stats.ClientEvictions
	}
	if delta := stats.ReputationDeferrals - a.sustainedLastDeferrals; delta > 0 {
		metrics.SustainedReputationDeferrals.Add(float64(delta))
		a.sustainedLastDeferrals = stats.ReputationDeferrals
	}
	if stats.LongDeferredClients > 0 {
		logrus.WithField("clients", stats.LongDeferredClients).
			Debug("Good-reputation clients sitting between the base and raised sustained-download thresholds")
	}
}

func (a *Analyzer) actOnSustainedDecision(decision sustained.Decision, enforcing bool) {
	path := decision.Path
	if path == "" {
		path = "hold"
	}
	outcome := "would_block"
	if enforcing {
		outcome = "blocked"
	}
	metrics.SustainedDecisions.WithLabelValues(path, outcome).Inc()

	fields := logrus.Fields{
		"ip":               decision.IP,
		"path":             path,
		"requests":         decision.Requests,
		"bytes":            decision.Bytes,
		"resources":        decision.Resources,
		"sections":         decision.Sections,
		"good_reputation":  decision.GoodReputation,
		"threshold_factor": decision.ThresholdFactor,
		"held":             decision.Held,
	}

	if !enforcing {
		logrus.WithFields(fields).Info("Sustained download detected (detect-only, not blocking)")
		return
	}

	ip := net.ParseIP(decision.IP)
	if ip == nil {
		logrus.WithFields(fields).Error("Sustained download decision carried an unparseable IP; not blocking")
		return
	}
	// Collectors index blocks by address family, so hand them a 4-byte address
	// for IPv4 rather than the 16-byte v4-in-v6 form ParseIP returns.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	logrus.WithFields(fields).Warn("Sustained download detected; blocking")
	metrics.HAProxyBlocks.Inc()

	// Penalize on the selecting crossing only. A held client is re-broadcast to
	// keep the block alive across collector restarts, but penalizing it again
	// every publish interval would compound a single detection into an
	// ever-worsening reputation for as long as the hold runs.
	if !decision.Held {
		a.ReputationHelper.PenalizeIP(ip, 15.0, "Sustained download: "+path)
	}

	a.Broadcast(&apiv1.Command{
		Type:   apiv1.CommandType_COMMAND_BLOCK_IP,
		Ip:     ip,
		Reason: "Sustained download (" + path + ")",
	})
}
