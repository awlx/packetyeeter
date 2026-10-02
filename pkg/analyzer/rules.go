package analyzer

import (
	"context"
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

// ruleSyncTimeout bounds how long PushRules waits for collector sends; a
// collector that stops reading must not hang the controller. Var for tests.
var ruleSyncTimeout = 10 * time.Second

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
// gRPC listener is unauthenticated, and rules can drop traffic.
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
// many were, waiting at most ruleSyncTimeout or until ctx ends.
func (a *Analyzer) syncScrubCollectors(ctx context.Context) int {
	a.collectorsMu.RLock()
	var scrub []*collectorStream
	for _, cs := range a.collectors {
		if cs.isScrub() {
			scrub = append(scrub, cs)
		}
	}
	a.collectorsMu.RUnlock()

	results := make(chan bool, len(scrub))
	for _, cs := range scrub {
		go func() {
			err := a.syncRules(cs)
			if err != nil {
				logrus.WithError(err).Warn("Failed to send rules to scrub collector")
			}
			results <- err == nil
		}()
	}
	timeout := time.NewTimer(ruleSyncTimeout)
	defer timeout.Stop()
	synced := 0
	for range scrub {
		select {
		case ok := <-results:
			if ok {
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

// syncRules sends one collector the difference between what it was last sent
// and what it should hold. Holding rulesMu across the diff and the send keeps
// deltas for one collector in order. The first sync on a stream replaces the
// collector's whole set, clearing rules a restarted analyzer no longer knows.
func (a *Analyzer) syncRules(cs *collectorStream) error {
	cs.rulesMu.Lock()
	defer cs.rulesMu.Unlock()

	want := a.rules.desired(time.Now(), a.Enforcing())
	delta := &apiv1.RuleSetDelta{Replace: !cs.rulesSynced}
	for id, r := range want {
		if prev, ok := cs.sentRules[id]; delta.Replace || !ok || !proto.Equal(prev, r) {
			delta.Upsert = append(delta.Upsert, r)
		}
	}
	if !delta.Replace {
		for id := range cs.sentRules {
			if _, ok := want[id]; !ok {
				delta.Remove = append(delta.Remove, id)
			}
		}
		if len(delta.Upsert) == 0 && len(delta.Remove) == 0 {
			return nil
		}
	}
	slices.SortFunc(delta.Upsert, func(x, y *apiv1.Rule) int { return strings.Compare(x.GetId(), y.GetId()) })
	slices.Sort(delta.Remove)

	cmd := &apiv1.Command{
		Id:        fmt.Sprintf("rules-%d", time.Now().UnixNano()),
		Timestamp: timestamppb.Now(),
		Type:      apiv1.CommandType_COMMAND_SET_RULES,
		Rules:     delta,
		Source:    "analyzer",
	}
	cs.sendMu.Lock()
	err := cs.stream.Send(cmd)
	cs.sendMu.Unlock()
	if err != nil {
		return err
	}
	cs.sentRules = want
	cs.rulesSynced = true
	metrics.RuleDeltasSent.Inc()
	return nil
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
	// Only on becoming scrub: repeated announcements must not pile up
	// goroutines behind a send that blocks.
	if role == "scrub" && prev != "scrub" {
		go func() {
			if err := a.syncRules(cs); err != nil {
				logrus.WithError(err).WithField("collector", collectorID).Warn("Failed to send rules to scrub collector")
			}
		}()
	}
}

func isRoleSignal(sig *apiv1.Signal) bool {
	_, ok := sig.GetMetadata()["role"]
	return ok && sig.GetType() == apiv1.SignalType_SIGNAL_UNKNOWN
}
