package analyzer

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/patterns"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ruleExpiry = timestamppb.New(time.Now().Add(time.Hour))

func testRule(id, dst string, action apiv1.RuleAction) *apiv1.Rule {
	r := &apiv1.Rule{
		Id:        id,
		DstPrefix: dst,
		Action:    action,
		ExpiresAt: ruleExpiry,
	}
	if action == apiv1.RuleAction_RULE_ACTION_RATE_LIMIT {
		r.RatePps = 1000
	}
	return r
}

func dropRule(id string) *apiv1.Rule {
	return testRule(id, "198.51.100.0/24", apiv1.RuleAction_RULE_ACTION_DROP)
}

func newRuleAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	a := newTestAnalyzer(t)
	a.Config.EnableRuleAPI = true
	return a
}

// addCollector registers a stream and, if role is set, announces it. A scrub
// announcement triggers an initial replace delta, which is returned.
func addCollector(t *testing.T, a *Analyzer, role string) (*fakeCollectorStream, *apiv1.RuleSetDelta) {
	t.Helper()
	fake := newFakeCollectorStream()
	cs := &collectorStream{stream: fake}
	id := a.registerCollector(context.Background(), cs)
	if role == "" {
		return fake, nil
	}
	a.handleRoleSignal(id, cs, roleSignal(role))
	if role != "scrub" {
		return fake, nil
	}
	return fake, rulesDelta(t, fake.waitForCommand(t))
}

func roleSignal(role string) *apiv1.Signal {
	return &apiv1.Signal{
		Type:     apiv1.SignalType_SIGNAL_UNKNOWN,
		Metadata: map[string]string{"role": role, "node": "n1"},
	}
}

func rulesDelta(t *testing.T, cmd *apiv1.Command) *apiv1.RuleSetDelta {
	t.Helper()
	if cmd.GetType() != apiv1.CommandType_COMMAND_SET_RULES || cmd.GetRules() == nil {
		t.Fatalf("command = %v, want COMMAND_SET_RULES with a delta", cmd)
	}
	return cmd.GetRules()
}

func upsertIDs(d *apiv1.RuleSetDelta) []string {
	ids := []string{}
	for _, r := range d.GetUpsert() {
		ids = append(ids, r.GetId())
	}
	return ids
}

func assertIDs(t *testing.T, what string, got, want []string) {
	t.Helper()
	got = slices.Sorted(slices.Values(got))
	want = slices.Sorted(slices.Values(want))
	if !slices.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

func push(t *testing.T, a *Analyzer, scope string, rules ...*apiv1.Rule) *apiv1.PushRulesAck {
	t.Helper()
	ack, err := a.PushRules(context.Background(), &apiv1.RuleSet{Scope: scope, Rules: rules})
	if err != nil {
		t.Fatalf("PushRules(%q): %v", scope, err)
	}
	return ack
}

func TestPushRulesDisabledByDefault(t *testing.T) {
	a := newTestAnalyzer(t)
	fake, _ := addCollector(t, a, "scrub")

	_, err := a.PushRules(context.Background(), &apiv1.RuleSet{Scope: "ctl", Rules: []*apiv1.Rule{dropRule("r1")}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if len(a.rules.scopes) != 0 {
		t.Fatalf("rules stored with the API disabled: %v", a.rules.scopes)
	}
	fake.expectNoCommand(t)
}

func TestPushRulesRejectsInvalidInput(t *testing.T) {
	noExpiry := dropRule("r1")
	noExpiry.ExpiresAt = nil

	tests := []struct {
		name string
		rs   *apiv1.RuleSet
	}{
		{"empty scope", &apiv1.RuleSet{Rules: []*apiv1.Rule{dropRule("r1")}}},
		{"scope with separator", &apiv1.RuleSet{Scope: "a/b", Rules: []*apiv1.Rule{dropRule("r1")}}},
		{"missing expires_at", &apiv1.RuleSet{Scope: "ctl", Rules: []*apiv1.Rule{noExpiry}}},
		{"bad dst_prefix", &apiv1.RuleSet{Scope: "ctl", Rules: []*apiv1.Rule{testRule("r1", "nope", apiv1.RuleAction_RULE_ACTION_DROP)}}},
		{"duplicate id", &apiv1.RuleSet{Scope: "ctl", Rules: []*apiv1.Rule{dropRule("r1"), dropRule("r1")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newRuleAnalyzer(t)
			fake, _ := addCollector(t, a, "scrub")

			_, err := a.PushRules(context.Background(), tt.rs)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if len(a.rules.scopes) != 0 {
				t.Fatalf("invalid set was stored: %v", a.rules.scopes)
			}
			fake.expectNoCommand(t)
		})
	}
}

func TestPushRulesRejectsSetExceedingCapacityAcrossScopes(t *testing.T) {
	a := newRuleAnalyzer(t)
	fake, _ := addCollector(t, a, "scrub")

	var first, second []*apiv1.Rule
	for i := range 20 {
		first = append(first, testRule(fmt.Sprintf("r%d", i), "203.0.113.7/32", apiv1.RuleAction_RULE_ACTION_DROP))
	}
	for i := range 13 {
		second = append(second, testRule(fmt.Sprintf("r%d", i), "203.0.113.7/32", apiv1.RuleAction_RULE_ACTION_DROP))
	}

	push(t, a, "a", first...)
	assertIDs(t, "first push upserts", upsertIDs(rulesDelta(t, fake.waitForCommand(t))), func() []string {
		var ids []string
		for _, r := range first {
			ids = append(ids, "a/"+r.GetId())
		}
		return ids
	}())

	_, err := a.PushRules(context.Background(), &apiv1.RuleSet{Scope: "b", Rules: second})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument for 33 rules covering one destination", err)
	}
	if _, ok := a.rules.scopes["b"]; ok {
		t.Fatal("over-capacity scope was stored")
	}
	if len(a.rules.scopes["a"]) != 20 {
		t.Fatalf("scope a has %d rules, want 20", len(a.rules.scopes["a"]))
	}
	fake.expectNoCommand(t)
}

func TestPushRulesReachesOnlyScrubCollectors(t *testing.T) {
	a := newRuleAnalyzer(t)
	scrub1, _ := addCollector(t, a, "scrub")
	scrub2, _ := addCollector(t, a, "scrub")
	host, _ := addCollector(t, a, "host")
	silent, _ := addCollector(t, a, "")

	ack := push(t, a, "ctl", dropRule("r1"))
	if ack.GetCollectors() != 2 {
		t.Fatalf("ack.collectors = %d, want 2", ack.GetCollectors())
	}
	for _, f := range []*fakeCollectorStream{scrub1, scrub2} {
		assertIDs(t, "upsert", upsertIDs(rulesDelta(t, f.waitForCommand(t))), []string{"ctl/r1"})
	}
	host.expectNoCommand(t)
	silent.expectNoCommand(t)
}

func TestPushRulesScopesWireIDs(t *testing.T) {
	a := newRuleAnalyzer(t)
	fake, _ := addCollector(t, a, "scrub")

	push(t, a, "a", dropRule("x"))
	assertIDs(t, "upsert", upsertIDs(rulesDelta(t, fake.waitForCommand(t))), []string{"a/x"})
	push(t, a, "b", dropRule("x"))
	assertIDs(t, "upsert", upsertIDs(rulesDelta(t, fake.waitForCommand(t))), []string{"b/x"})

	want := a.rules.desired(time.Now(), true)
	assertIDs(t, "desired", slices.Collect(maps.Keys(want)), []string{"a/x", "b/x"})

	push(t, a, "a")
	d := rulesDelta(t, fake.waitForCommand(t))
	if d.GetReplace() || len(d.GetUpsert()) != 0 {
		t.Fatalf("clearing scope a sent replace=%v upsert=%v, want only removes", d.GetReplace(), upsertIDs(d))
	}
	assertIDs(t, "remove", d.GetRemove(), []string{"a/x"})
	if _, ok := a.rules.scopes["b"]["b/x"]; !ok {
		t.Fatal("clearing scope a removed scope b's rule")
	}
}

func TestSyncRulesSendsReplaceThenDifferences(t *testing.T) {
	a := newRuleAnalyzer(t)
	fake, first := addCollector(t, a, "scrub")
	if !first.GetReplace() || len(first.GetUpsert()) != 0 || len(first.GetRemove()) != 0 {
		t.Fatalf("first delta = %v, want an empty replace", first)
	}

	push(t, a, "ctl", dropRule("r1"), dropRule("r2"), dropRule("r3"))
	d := rulesDelta(t, fake.waitForCommand(t))
	if d.GetReplace() {
		t.Fatal("second delta on a stream must not replace")
	}
	assertIDs(t, "upsert", upsertIDs(d), []string{"ctl/r1", "ctl/r2", "ctl/r3"})

	changed := dropRule("r2")
	changed.Priority = 7
	push(t, a, "ctl", dropRule("r1"), changed, dropRule("r4"))
	d = rulesDelta(t, fake.waitForCommand(t))
	if d.GetReplace() {
		t.Fatal("incremental delta must not replace")
	}
	assertIDs(t, "upsert", upsertIDs(d), []string{"ctl/r2", "ctl/r4"})
	assertIDs(t, "remove", d.GetRemove(), []string{"ctl/r3"})

	push(t, a, "ctl", dropRule("r1"), changed, dropRule("r4"))
	fake.expectNoCommand(t)
}

func TestScrubCollectorAnnouncingLateGetsFullUnion(t *testing.T) {
	a := newRuleAnalyzer(t)
	if ack := push(t, a, "a", dropRule("x")); ack.GetCollectors() != 0 {
		t.Fatalf("ack.collectors = %d with no scrub collectors, want 0", ack.GetCollectors())
	}
	push(t, a, "b", dropRule("x"), testRule("y", "2001:db8::/48", apiv1.RuleAction_RULE_ACTION_PASS))

	_, d := addCollector(t, a, "scrub")
	if !d.GetReplace() {
		t.Fatal("first delta to a late scrub collector must replace")
	}
	assertIDs(t, "upsert", upsertIDs(d), []string{"a/x", "b/x", "b/y"})
	if len(d.GetRemove()) != 0 {
		t.Fatalf("replace delta carries removes: %v", d.GetRemove())
	}
}

func mixedRules() []*apiv1.Rule {
	return []*apiv1.Rule{
		testRule("drop", "198.51.100.0/24", apiv1.RuleAction_RULE_ACTION_DROP),
		testRule("pass", "198.51.100.10/32", apiv1.RuleAction_RULE_ACTION_PASS),
		testRule("rl", "2001:db8::/32", apiv1.RuleAction_RULE_ACTION_RATE_LIMIT),
	}
}

func TestDryRunSendsOnlyPassRules(t *testing.T) {
	a := newRuleAnalyzer(t)
	a.Config.DryRun = true
	fake, _ := addCollector(t, a, "scrub")

	push(t, a, "ctl", mixedRules()...)
	assertIDs(t, "upsert", upsertIDs(rulesDelta(t, fake.waitForCommand(t))), []string{"ctl/pass"})

	_, late := addCollector(t, a, "scrub")
	assertIDs(t, "late replace upsert", upsertIDs(late), []string{"ctl/pass"})
}

func TestStopEnforcementWithdrawsRestrictingRules(t *testing.T) {
	a := newRuleAnalyzer(t)
	fake, _ := addCollector(t, a, "scrub")

	push(t, a, "ctl", mixedRules()...)
	assertIDs(t, "upsert", upsertIDs(rulesDelta(t, fake.waitForCommand(t))), []string{"ctl/drop", "ctl/pass", "ctl/rl"})

	a.StopEnforcement("test")
	d := rulesDelta(t, fake.waitForCommand(t))
	if d.GetReplace() || len(d.GetUpsert()) != 0 {
		t.Fatalf("withdrawal delta replace=%v upsert=%v, want only removes", d.GetReplace(), upsertIDs(d))
	}
	assertIDs(t, "remove", d.GetRemove(), []string{"ctl/drop", "ctl/rl"})

	push(t, a, "other", dropRule("d2"), testRule("p2", "192.0.2.0/24", apiv1.RuleAction_RULE_ACTION_PASS))
	d = rulesDelta(t, fake.waitForCommand(t))
	assertIDs(t, "upsert after stop", upsertIDs(d), []string{"other/p2"})
}

func TestRuleStoreDesiredDropsExpiredRules(t *testing.T) {
	now := time.Now()
	short := dropRule("short")
	short.Id = "ctl/short"
	short.ExpiresAt = timestamppb.New(now.Add(ruleExpiryMargin + time.Second))
	long := dropRule("long")
	long.Id = "ctl/long"

	s := ruleStore{scopes: map[string]map[string]*apiv1.Rule{}}
	if err := s.replace("ctl", map[string]*apiv1.Rule{short.Id: short, long.Id: long}, now); err != nil {
		t.Fatalf("replace: %v", err)
	}

	tests := []struct {
		at   time.Time
		want []string
	}{
		{now, []string{"ctl/long", "ctl/short"}},
		{now.Add(time.Second + time.Millisecond), []string{"ctl/long"}}, // within the margin: withheld
		{now, []string{"ctl/long", "ctl/short"}},
		{now.Add(ruleExpiryMargin + time.Second), []string{"ctl/long"}}, // expired: deleted
		{now, []string{"ctl/long"}},
		{now.Add(2 * time.Hour), nil},
	}
	for i, tt := range tests {
		got := slices.Collect(maps.Keys(s.desired(tt.at, true)))
		assertIDs(t, fmt.Sprintf("step %d desired", i), got, tt.want)
	}
	if len(s.scopes) != 0 {
		t.Fatalf("fully expired scope kept: %v", s.scopes)
	}
}

func TestExpiredRuleRemovedInNextDelta(t *testing.T) {
	a := newRuleAnalyzer(t)
	fake, _ := addCollector(t, a, "scrub")

	short := dropRule("short")
	short.ExpiresAt = timestamppb.New(time.Now().Add(ruleExpiryMargin + 300*time.Millisecond))
	push(t, a, "a", short)
	assertIDs(t, "upsert", upsertIDs(rulesDelta(t, fake.waitForCommand(t))), []string{"a/short"})

	time.Sleep(400 * time.Millisecond)
	push(t, a, "b", dropRule("x"))
	d := rulesDelta(t, fake.waitForCommand(t))
	assertIDs(t, "upsert", upsertIDs(d), []string{"b/x"})
	assertIDs(t, "remove", d.GetRemove(), []string{"a/short"})
}

func TestIsRoleSignal(t *testing.T) {
	tests := []struct {
		name string
		sig  *apiv1.Signal
		want bool
	}{
		{"role on unknown", roleSignal("scrub"), true},
		{"empty role on unknown", &apiv1.Signal{Metadata: map[string]string{"role": ""}}, true},
		{"unknown without role", &apiv1.Signal{Metadata: map[string]string{"node": "n1"}}, false},
		{"unknown without metadata", &apiv1.Signal{}, false},
		{"role on syn flood", &apiv1.Signal{Type: apiv1.SignalType_SIGNAL_SYN_FLOOD, Metadata: map[string]string{"role": "scrub"}}, false},
		{"role on tcp metadata", &apiv1.Signal{Type: apiv1.SignalType_SIGNAL_TCP_METADATA, Metadata: map[string]string{"role": "scrub"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRoleSignal(tt.sig); got != tt.want {
				t.Fatalf("isRoleSignal = %v, want %v", got, tt.want)
			}
		})
	}
}

type recvCollectorStream struct {
	*fakeCollectorStream
	ctx  context.Context
	recv chan *apiv1.Signal
}

func (s *recvCollectorStream) Context() context.Context { return s.ctx }

func (s *recvCollectorStream) Recv() (*apiv1.Signal, error) {
	sig, ok := <-s.recv
	if !ok {
		return nil, io.EOF
	}
	return sig, nil
}

func TestStreamSignalsDoesNotScoreRoleSignals(t *testing.T) {
	a := newRuleAnalyzer(t)
	a.PatternTracker = patterns.NewPatternTracker(nil)
	roleIP := net.ParseIP("192.0.2.80").To4()
	controlIP := net.ParseIP("192.0.2.81").To4()
	tcp := &apiv1.TCPContext{Ttl: 64, WindowSize: 65535, Mss: 1460}

	s := &recvCollectorStream{
		fakeCollectorStream: newFakeCollectorStream(),
		ctx:                 context.Background(),
		recv:                make(chan *apiv1.Signal, 2),
	}
	s.recv <- &apiv1.Signal{Ip: roleIP, TcpContext: tcp, Metadata: map[string]string{"role": "scrub"}}
	s.recv <- &apiv1.Signal{Ip: controlIP, TcpContext: tcp, Metadata: map[string]string{"node": "n1"}}

	done := make(chan error, 1)
	go func() { done <- a.StreamSignals(s) }()

	if d := rulesDelta(t, s.waitForCommand(t)); !d.GetReplace() {
		t.Fatal("role signal over the stream did not trigger a replace delta")
	}
	close(s.recv)
	if err := <-done; err != nil {
		t.Fatalf("StreamSignals: %v", err)
	}

	if a.PatternTracker.GetPattern(controlIP) == nil {
		t.Fatal("control signal was not processed; the assertion below would prove nothing")
	}
	if p := a.PatternTracker.GetPattern(roleIP); p != nil {
		t.Fatalf("role signal reached processSignal: %+v", p)
	}
}

func TestPushRulesRejectsSetTooLargeToSend(t *testing.T) {
	a := newRuleAnalyzer(t)
	fake, _ := addCollector(t, a, "scrub")

	big := func(id string) *apiv1.Rule {
		r := dropRule(id)
		r.Id = id + strings.Repeat("x", maxRuleSetBytes/2)
		return r
	}
	push(t, a, "a", big("r"))
	fake.waitForCommand(t)

	_, err := a.PushRules(context.Background(), &apiv1.RuleSet{Scope: "b", Rules: []*apiv1.Rule{big("r")}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument for a union too large for one replace delta", err)
	}
	if _, ok := a.rules.scopes["b"]; ok {
		t.Fatal("oversized scope was stored")
	}
	fake.expectNoCommand(t)
}

func TestDesiredWithholdsRulesNearExpiry(t *testing.T) {
	now := time.Now()
	soon := dropRule("soon")
	soon.Id = "ctl/soon"
	soon.ExpiresAt = timestamppb.New(now.Add(ruleExpiryMargin / 2))
	s := ruleStore{scopes: map[string]map[string]*apiv1.Rule{"ctl": {soon.Id: soon}}}
	if got := s.desired(now, true); len(got) != 0 {
		t.Fatalf("desired = %v, want a rule about to expire withheld", slices.Collect(maps.Keys(got)))
	}
}

// blockingCollectorStream never completes a Send, like a collector that
// stopped reading.
type blockingCollectorStream struct {
	apiv1.AnalyzerService_StreamSignalsServer
	release chan struct{}
}

func (b *blockingCollectorStream) Send(*apiv1.Command) error {
	<-b.release
	return nil
}

func addBlockedScrubCollector(t *testing.T, a *Analyzer) *collectorStream {
	t.Helper()
	b := &blockingCollectorStream{release: make(chan struct{})}
	t.Cleanup(func() { close(b.release) })
	cs := &collectorStream{stream: b}
	cs.setRole("scrub")
	a.registerCollector(context.Background(), cs)
	return cs
}

func TestPushRulesDoesNotHangOnBlockedCollector(t *testing.T) {
	a := newRuleAnalyzer(t)
	prev := ruleSyncTimeout
	ruleSyncTimeout = 100 * time.Millisecond
	t.Cleanup(func() { ruleSyncTimeout = prev })
	addBlockedScrubCollector(t, a)
	fake, _ := addCollector(t, a, "scrub")

	done := make(chan *apiv1.PushRulesAck, 1)
	go func() { done <- push(t, a, "ctl", dropRule("r1")) }()
	select {
	case ack := <-done:
		if ack.GetCollectors() != 1 {
			t.Fatalf("collectors = %d, want 1 (the responsive one)", ack.GetCollectors())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PushRules hung on a collector that does not read")
	}
	assertIDs(t, "upsert", upsertIDs(rulesDelta(t, fake.waitForCommand(t))), []string{"ctl/r1"})
}

func TestRepeatedRoleAnnouncementsStartOneSync(t *testing.T) {
	a := newRuleAnalyzer(t)
	b := &blockingCollectorStream{release: make(chan struct{})}
	cs := &collectorStream{stream: b}
	id := a.registerCollector(context.Background(), cs)

	before := runtime.NumGoroutine()
	for range 200 {
		a.handleRoleSignal(id, cs, roleSignal("scrub"))
	}
	if n := runtime.NumGoroutine() - before; n > 50 {
		t.Fatalf("%d goroutines started by repeated role announcements, want 1", n)
	}
	close(b.release)
}
