package analyzer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/metrics"
	"PacketYeeter/pkg/scrubrules"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Rule ids on the wire are "<scope>/<id>", so two controllers can use the
// same id without overwriting each other on a collector.
const ruleScopeSep = "/"

const (
	// A collector rejects a whole delta holding a rule that has expired by
	// its clock, and the analyzer cannot tell, so rules this close to expiry
	// are withdrawn instead of sent.
	ruleExpiryMargin = 5 * time.Second

	// Stays under the collectors' default 4 MiB gRPC receive limit, which a
	// replace delta carrying every scope's rules must fit.
	maxRuleSetBytes = 3 << 20
)

// defaultRuleSyncTimeout bounds how long PushRules waits for collector sends; a
// collector that stops reading must not hang the controller.
const defaultRuleSyncTimeout = 10 * time.Second

// ruleStore holds the desired runtime rules per scope.
type ruleStore struct {
	mu     sync.Mutex
	scopes map[string]map[string]*apiv1.Rule // scope -> wire id -> rule
}

// replace sets one scope's rules after checking that the union of all scopes
// still fits the scrub collectors' limits; an empty set removes the scope.
func (s *ruleStore) replace(scope string, rules map[string]*apiv1.Rule, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	parsed := map[string]*scrubrules.Rule{}
	size := 0
	for sc, set := range s.scopes {
		if sc == scope {
			continue
		}
		for id, r := range set {
			if p, err := scrubrules.Parse(r, now); err == nil {
				parsed[id] = p
				size += proto.Size(r)
			}
		}
	}
	for id, r := range rules {
		p, err := scrubrules.Parse(r, now)
		if err != nil {
			return err
		}
		parsed[id] = p
		size += proto.Size(r)
	}
	if err := scrubrules.CheckCapacity(parsed); err != nil {
		return fmt.Errorf("rule set does not fit alongside the other scopes: %w", err)
	}
	if size > maxRuleSetBytes {
		return fmt.Errorf("rule set does not fit alongside the other scopes: %d bytes encoded, at most %d", size, maxRuleSetBytes)
	}

	if len(rules) == 0 {
		delete(s.scopes, scope)
		metrics.RulesDesired.DeleteLabelValues(scope)
		return nil
	}
	s.scopes[scope] = rules
	metrics.RulesDesired.WithLabelValues(scope).Set(float64(len(rules)))
	return nil
}

// desired returns the rules every scrub collector should hold now. Expired
// rules are dropped from the store, since a collector rejects a delta that
// contains one. When the analyzer is not enforcing (-dry-run or the kill
// switch), only PASS rules are sent: they relieve traffic, never restrict it.
func (s *ruleStore) desired(now time.Time, enforcing bool) map[string]*apiv1.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := map[string]*apiv1.Rule{}
	for scope, set := range s.scopes {
		for id, r := range set {
			expires := r.GetExpiresAt().AsTime()
			if !now.Before(expires) {
				delete(set, id)
				continue
			}
			if !now.Add(ruleExpiryMargin).Before(expires) {
				continue
			}
			if enforcing || r.GetAction() == apiv1.RuleAction_RULE_ACTION_PASS {
				out[id] = r
			}
		}
		if len(set) == 0 {
			delete(s.scopes, scope)
			metrics.RulesDesired.DeleteLabelValues(scope)
		} else {
			metrics.RulesDesired.WithLabelValues(scope).Set(float64(len(set)))
		}
	}
	return out
}

// PushRules replaces one scope's rules and sends the resulting changes to
// every scrub collector. It is off unless enabled because the analyzer's
// gRPC listener is unauthenticated without mTLS, and rules can drop traffic.
func (a *Analyzer) PushRules(ctx context.Context, rs *apiv1.RuleSet) (*apiv1.PushRulesAck, error) {
	if !a.Config.EnableRuleAPI {
		return nil, status.Error(codes.PermissionDenied, "rule API disabled; start the analyzer with -enable-rule-api")
	}
	scope := rs.GetScope()
	if scope == "" || strings.Contains(scope, ruleScopeSep) {
		return nil, status.Errorf(codes.InvalidArgument, "scope must be non-empty and must not contain %q", ruleScopeSep)
	}

	now := time.Now()
	wire := make(map[string]*apiv1.Rule, len(rs.GetRules()))
	for _, r := range rs.GetRules() {
		if _, err := scrubrules.Parse(r, now); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		w := proto.Clone(r).(*apiv1.Rule)
		w.Id = scope + ruleScopeSep + r.GetId()
		if _, dup := wire[w.Id]; dup {
			return nil, status.Errorf(codes.InvalidArgument, "rule %q appears twice", r.GetId())
		}
		wire[w.Id] = w
	}
	if err := a.rules.replace(scope, wire, now); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	a.persistRules()
	// Once per push, not per collector or resync: the stream reports decisions.
	a.publishCommand(a.ruleSetCommand())

	n := a.syncScrubCollectors(ctx)
	logrus.WithFields(logrus.Fields{
		"scope":      scope,
		"rules":      len(wire),
		"collectors": n,
		"enforcing":  a.Enforcing(),
	}).Info("Rule set pushed")
	return &apiv1.PushRulesAck{Collectors: uint32(n)}, nil
}

// syncScrubCollectors brings every scrub collector up to date and returns how
// many were, waiting at most the rule sync timeout or until ctx ends.
func (a *Analyzer) syncScrubCollectors(ctx context.Context) int {
	a.collectorsMu.RLock()
	var scrub []*collectorStream
	for _, cs := range a.collectors {
		if cs.isScrub() {
			scrub = append(scrub, cs)
		}
	}
	a.collectorsMu.RUnlock()

	results := make(chan error, len(scrub))
	for _, cs := range scrub {
		a.requestRuleSync(cs, results)
	}
	limit := a.ruleSyncTimeout
	if limit <= 0 {
		limit = defaultRuleSyncTimeout
	}
	timeout := time.NewTimer(limit)
	defer timeout.Stop()
	synced := 0
	for range scrub {
		select {
		case err := <-results:
			if err != nil {
				logrus.WithError(err).Warn("Failed to send rules to scrub collector")
			} else {
				synced++
			}
		case <-timeout.C:
			logrus.Warn("Timed out sending rules to scrub collectors; the rest are still being sent")
			return synced
		case <-ctx.Done():
			return synced
		}
	}
	return synced
}

// requestRuleSync makes sure the collector is sent its complete rule set,
// built after this call, and sends the result to res once; res must have room.
// Collectors do not acknowledge rule changes, so a change that was rejected
// or lost can only be repaired by sending everything again; every push and
// the periodic resync do that. Requests made while a send is running are
// coalesced into one more send, so a collector that stopped reading costs one
// blocked goroutine, not one per request.
func (a *Analyzer) requestRuleSync(cs *collectorStream, res chan<- error) {
	cs.syncMu.Lock()
	cs.syncWaiters = append(cs.syncWaiters, res)
	start := !cs.syncing
	cs.syncing = true
	cs.syncMu.Unlock()
	if start && !a.goTracked(func() { a.runRuleSyncs(cs) }) {
		cs.syncMu.Lock()
		waiters := cs.syncWaiters
		cs.syncWaiters, cs.syncing = nil, false
		cs.syncMu.Unlock()
		for _, w := range waiters {
			w <- errors.New("analyzer shutting down")
		}
	}
}

func (a *Analyzer) runRuleSyncs(cs *collectorStream) {
	for {
		cs.syncMu.Lock()
		waiters := cs.syncWaiters
		cs.syncWaiters = nil
		if len(waiters) == 0 {
			cs.syncing = false
			cs.syncMu.Unlock()
			return
		}
		cs.syncMu.Unlock()

		err := a.sendLocked(cs, a.ruleSetCommand())
		if err == nil {
			metrics.RuleDeltasSent.Inc()
		}
		for _, w := range waiters {
			w <- err
		}
	}
}

// ruleSetCommand builds the full replacement rule set every scrub collector
// should hold now.
func (a *Analyzer) ruleSetCommand() *apiv1.Command {
	want := a.rules.desired(time.Now(), a.Enforcing())
	delta := &apiv1.RuleSetDelta{Replace: true, Upsert: make([]*apiv1.Rule, 0, len(want))}
	for _, r := range want {
		delta.Upsert = append(delta.Upsert, r)
	}
	slices.SortFunc(delta.Upsert, func(x, y *apiv1.Rule) int { return strings.Compare(x.GetId(), y.GetId()) })
	return &apiv1.Command{
		Id:        fmt.Sprintf("rules-%d", time.Now().UnixNano()),
		Timestamp: timestamppb.Now(),
		Type:      apiv1.CommandType_COMMAND_SET_RULES,
		Rules:     delta,
		Source:    "analyzer",
	}
}

// ruleResyncInterval bounds how long a scrub collector can stay out of sync
// after a rule change it rejected or never received.
const ruleResyncInterval = time.Minute

func (a *Analyzer) runRuleResync() {
	defer a.wg.Done()
	ticker := time.NewTicker(ruleResyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.syncScrubCollectors(a.ctx)
		}
	}
}

// handleRoleSignal records a collector's announced role. It is never scored:
// it says what the collector is, not what it saw.
func (a *Analyzer) handleRoleSignal(collectorID string, cs *collectorStream, sig *apiv1.Signal) {
	role := sig.GetMetadata()["role"]
	prev := cs.setRole(role)
	logrus.WithFields(logrus.Fields{
		"collector": collectorID,
		"role":      role,
		"node":      sig.GetMetadata()["node"],
	}).Info("Collector announced its role")
	if role == "scrub" && !cs.certTrusted && len(a.Config.ScrubClientNames) > 0 && cs.warnedUntrusted.CompareAndSwap(false, true) {
		logrus.WithField("collector", collectorID).Warn("Collector announced scrub mode but its certificate is not on -scrub-client-names; its blocks are not fanned out to other scrub collectors and it receives none")
	}
	// Only on becoming scrub: repeated announcements must not pile up
	// goroutines behind a send that blocks.
	if role == "scrub" && prev != "scrub" {
		res := make(chan error, 1)
		a.requestRuleSync(cs, res)
		a.goTracked(func() {
			if err := <-res; err != nil {
				logrus.WithError(err).WithField("collector", collectorID).Warn("Failed to send rules to scrub collector")
			}
		})
	}
}

func isRoleSignal(sig *apiv1.Signal) bool {
	_, ok := sig.GetMetadata()["role"]
	return ok && sig.GetType() == apiv1.SignalType_SIGNAL_UNKNOWN
}
