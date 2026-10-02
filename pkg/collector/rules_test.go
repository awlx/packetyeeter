package collector

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"
)

var ruleT0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type fakeRuleMaps struct {
	bodies  map[uint16]ebpf.ScrubRule
	puts    []uint16
	resets  []uint16
	tries   [2]map[netip.Prefix][]uint16
	swaps   [2][]map[netip.Prefix][]uint16
	putErr  error
	swapErr [2]error
	// swapFail, when set, decides each swap's error by family and call number.
	swapFail func(fam, call int) error
	calls    [2]int
}

func newFakeRuleMaps() *fakeRuleMaps {
	return &fakeRuleMaps{bodies: map[uint16]ebpf.ScrubRule{}}
}

func (f *fakeRuleMaps) PutRuleBody(slot uint16, r *ebpf.ScrubRule) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.puts = append(f.puts, slot)
	f.bodies[slot] = *r
	return nil
}

func (f *fakeRuleMaps) ResetRuleBucket(slot uint16) error {
	f.resets = append(f.resets, slot)
	return nil
}

func (f *fakeRuleMaps) SwapRuleTrie(v6 bool, entries map[netip.Prefix][]uint16) error {
	fam := 0
	if v6 {
		fam = 1
	}
	f.calls[fam]++
	if f.swapFail != nil {
		if err := f.swapFail(fam, f.calls[fam]); err != nil {
			return err
		}
	}
	if err := f.swapErr[fam]; err != nil {
		f.swapErr[fam] = nil
		return err
	}
	f.tries[fam] = entries
	f.swaps[fam] = append(f.swaps[fam], entries)
	return nil
}

type fakeRuleSnapshot struct {
	bodies map[uint16]ebpf.ScrubRule
	puts   int
	resets int
	swaps  [2]int
}

func (f *fakeRuleMaps) snapshot() fakeRuleSnapshot {
	return fakeRuleSnapshot{
		bodies: maps.Clone(f.bodies),
		puts:   len(f.puts),
		resets: len(f.resets),
		swaps:  [2]int{len(f.swaps[0]), len(f.swaps[1])},
	}
}

func testRule(id, dst string, prio uint32, mods ...func(*apiv1.Rule)) *apiv1.Rule {
	r := &apiv1.Rule{
		Id:        id,
		DstPrefix: dst,
		Action:    apiv1.RuleAction_RULE_ACTION_DROP,
		Priority:  prio,
		ExpiresAt: timestamppb.New(ruleT0.Add(time.Hour)),
	}
	for _, m := range mods {
		m(r)
	}
	return r
}

func upsert(rules ...*apiv1.Rule) *apiv1.RuleSetDelta {
	return &apiv1.RuleSetDelta{Upsert: rules}
}

func mustApply(t *testing.T, e *ruleEngine, d *apiv1.RuleSetDelta, now time.Time) ruleApplyResult {
	t.Helper()
	res, err := e.Apply(d, now)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return res
}

func slotOf(t *testing.T, e *ruleEngine, id string) uint16 {
	t.Helper()
	ir, ok := e.installed[id]
	if !ok {
		t.Fatalf("rule %q not installed", id)
	}
	return ir.slot
}

func ruleIDs(e *ruleEngine) []string {
	return slices.Sorted(maps.Keys(e.rules))
}

func TestRuleValidation(t *testing.T) {
	ranges := func(n int) []*apiv1.PortRange {
		out := make([]*apiv1.PortRange, n)
		for i := range out {
			out[i] = &apiv1.PortRange{From: uint32(i), To: uint32(i)}
		}
		return out
	}
	srcs := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("10.0.%d.0/24", i)
		}
		return out
	}
	tests := []struct {
		name string
		mod  func(*apiv1.Rule)
	}{
		{"empty id", func(r *apiv1.Rule) { r.Id = "" }},
		{"missing dst_prefix", func(r *apiv1.Rule) { r.DstPrefix = "" }},
		{"bad dst_prefix", func(r *apiv1.Rule) { r.DstPrefix = "203.0.113.300/24" }},
		{"dst without length", func(r *apiv1.Rule) { r.DstPrefix = "203.0.113.1" }},
		{"missing expires_at", func(r *apiv1.Rule) { r.ExpiresAt = nil }},
		{"past expires_at", func(r *apiv1.Rule) { r.ExpiresAt = timestamppb.New(ruleT0.Add(-time.Second)) }},
		{"expires_at now", func(r *apiv1.Rule) { r.ExpiresAt = timestamppb.New(ruleT0) }},
		{"unspecified action", func(r *apiv1.Rule) { r.Action = apiv1.RuleAction_RULE_ACTION_UNSPECIFIED }},
		{"rate limit without pps", func(r *apiv1.Rule) { r.Action = apiv1.RuleAction_RULE_ACTION_RATE_LIMIT }},
		{"protocol > 255", func(r *apiv1.Rule) { r.Protocols = []uint32{6, 256} }},
		{"9 src port ranges", func(r *apiv1.Rule) { r.SrcPorts = ranges(9) }},
		{"9 dst port ranges", func(r *apiv1.Rule) { r.DstPorts = ranges(9) }},
		{"src port from > to", func(r *apiv1.Rule) { r.SrcPorts = []*apiv1.PortRange{{From: 80, To: 79}} }},
		{"dst port from > to", func(r *apiv1.Rule) { r.DstPorts = []*apiv1.PortRange{{From: 443, To: 80}} }},
		{"src port > 65535", func(r *apiv1.Rule) { r.SrcPorts = []*apiv1.PortRange{{From: 1, To: 65536}} }},
		{"dst port > 65535", func(r *apiv1.Rule) { r.DstPorts = []*apiv1.PortRange{{From: 65536, To: 65536}} }},
		{"pkt_len from > to", func(r *apiv1.Rule) { r.PktLen = &apiv1.PortRange{From: 100, To: 60} }},
		{"tcp value outside mask", func(r *apiv1.Rule) { r.TcpFlagsMask, r.TcpFlagsValue = 0x02, 0x12 }},
		{"tcp mask > 255", func(r *apiv1.Rule) { r.TcpFlagsMask = 0x100 }},
		{"tcp value > 255", func(r *apiv1.Rule) { r.TcpFlagsMask, r.TcpFlagsValue = 0x1ff, 0x100 }},
		{"9 src prefixes", func(r *apiv1.Rule) { r.SrcPrefixes = srcs(9) }},
		{"bad src prefix", func(r *apiv1.Rule) { r.SrcPrefixes = []string{"nope"} }},
		{"ports without tcp or udp", func(r *apiv1.Rule) { r.Protocols, r.DstPorts = []uint32{1}, ranges(1) }},
		{"tcp flags without tcp", func(r *apiv1.Rule) { r.Protocols, r.TcpFlagsMask = []uint32{17}, 0x02 }},
		{"rate_pps on drop", func(r *apiv1.Rule) { r.RatePps = 100 }},
		{"v6 src for v4 dst", func(r *apiv1.Rule) { r.SrcPrefixes = []string{"2001:db8::/32"} }},
		{"v4 src for v6 dst", func(r *apiv1.Rule) { r.DstPrefix = "2001:db8::/32"; r.SrcPrefixes = []string{"10.0.0.0/8"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRuleMaps()
			e := newRuleEngine(f)
			mustApply(t, e, upsert(testRule("keep", "198.51.100.0/24", 1)), ruleT0)
			before := f.snapshot()

			bad := testRule("bad", "203.0.113.0/24", 1, tt.mod)
			_, err := e.Apply(&apiv1.RuleSetDelta{
				Upsert: []*apiv1.Rule{testRule("good", "192.0.2.0/24", 1), bad},
				Remove: []string{"keep"},
			}, ruleT0)
			if err == nil {
				t.Fatal("Apply accepted an invalid rule")
			}
			assertUnchanged(t, e, f, before, []string{"keep"})
		})
	}
}

func TestRuleValidationAccepts(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*apiv1.Rule)
	}{
		{"max src ports", func(r *apiv1.Rule) { r.SrcPorts = make([]*apiv1.PortRange, 8) }},
		{"port 65535", func(r *apiv1.Rule) { r.DstPorts = []*apiv1.PortRange{{From: 65535, To: 65535}} }},
		{"8 src prefixes", func(r *apiv1.Rule) {
			r.SrcPrefixes = []string{"10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", "10.4.0.0/16", "10.5.0.0/16", "10.6.0.0/16", "10.7.0.0/16"}
		}},
		{"tcp value within mask", func(r *apiv1.Rule) { r.TcpFlagsMask, r.TcpFlagsValue = 0x12, 0x02 }},
		{"rate limit", func(r *apiv1.Rule) { r.Action, r.RatePps = apiv1.RuleAction_RULE_ACTION_RATE_LIMIT, 1 }},
		{"v6", func(r *apiv1.Rule) { r.DstPrefix = "2001:db8::/32"; r.SrcPrefixes = []string{"2001:db8:1::/48"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseRule(testRule("r", "192.0.2.0/24", 1, tt.mod), ruleT0); err != nil {
				t.Fatalf("parseRule: %v", err)
			}
		})
	}
}

func assertUnchanged(t *testing.T, e *ruleEngine, f *fakeRuleMaps, before fakeRuleSnapshot, wantIDs []string) {
	t.Helper()
	if got := ruleIDs(e); !slices.Equal(got, wantIDs) {
		t.Errorf("engine rules = %v, want %v", got, wantIDs)
	}
	if after := f.snapshot(); !reflect.DeepEqual(after, before) {
		t.Errorf("kernel state changed: before %+v, after %+v", before, after)
	}
}

func TestRuleApplyDuplicateIDRejected(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)
	before := f.snapshot()
	_, err := e.Apply(upsert(testRule("a", "192.0.2.0/24", 1), testRule("a", "198.51.100.0/24", 2)), ruleT0)
	if err == nil {
		t.Fatal("Apply accepted the same id twice")
	}
	assertUnchanged(t, e, f, before, []string{})
}

func TestRuleApplyCapacityIsAllOrNothing(t *testing.T) {
	tests := []struct {
		name  string
		delta func() *apiv1.RuleSetDelta
	}{
		{"too many rules per destination", func() *apiv1.RuleSetDelta {
			var rules []*apiv1.Rule
			for i := 0; i <= ebpf.RulesPerDst; i++ {
				rules = append(rules, testRule(fmt.Sprintf("r%02d", i), fmt.Sprintf("10.0.0.0/%d", i), 1))
			}
			return upsert(rules...)
		}},
		{"too many rules per family", func() *apiv1.RuleSetDelta {
			var rules []*apiv1.Rule
			for i := 0; i <= ebpf.RulesMax; i++ {
				rules = append(rules, testRule(fmt.Sprintf("r%d", i), netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}).String()+"/24", 1))
			}
			return upsert(rules...)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRuleMaps()
			e := newRuleEngine(f)
			mustApply(t, e, upsert(testRule("keep", "198.51.100.0/24", 1)), ruleT0)
			before := f.snapshot()
			freeBefore := len(e.free)

			if _, err := e.Apply(tt.delta(), ruleT0); err == nil {
				t.Fatal("Apply accepted a delta over capacity")
			}
			assertUnchanged(t, e, f, before, []string{"keep"})
			if len(e.free) != freeBefore {
				t.Errorf("free slots = %d, want %d", len(e.free), freeBefore)
			}
		})
	}
}

func parsedRule(t *testing.T, id, dst string, prio uint32) *rule {
	t.Helper()
	r, err := parseRule(testRule(id, dst, prio), ruleT0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFlattenRules(t *testing.T) {
	tests := []struct {
		name  string
		rules [][3]any // id, dst, priority
		want  map[string][]string
	}{
		{
			name:  "broad lower priority listed under narrow",
			rules: [][3]any{{"wide", "10.0.0.0/16", 1}, {"host", "10.0.1.1/32", 2}},
			want: map[string][]string{
				"10.0.0.0/16": {"wide"},
				"10.0.1.1/32": {"wide", "host"},
			},
		},
		{
			name:  "narrow lower priority first",
			rules: [][3]any{{"wide", "10.0.0.0/16", 5}, {"host", "10.0.1.1/32", 2}},
			want: map[string][]string{
				"10.0.0.0/16": {"wide"},
				"10.0.1.1/32": {"host", "wide"},
			},
		},
		{
			name:  "ties broken by id",
			rules: [][3]any{{"b", "10.0.0.0/8", 1}, {"a", "10.0.0.0/24", 1}, {"c", "10.0.0.0/8", 1}},
			want: map[string][]string{
				"10.0.0.0/8":  {"b", "c"},
				"10.0.0.0/24": {"a", "b", "c"},
			},
		},
		{
			name:  "disjoint prefixes stay separate",
			rules: [][3]any{{"x", "10.0.0.0/24", 1}, {"y", "10.0.1.0/24", 1}},
			want: map[string][]string{
				"10.0.0.0/24": {"x"},
				"10.0.1.0/24": {"y"},
			},
		},
		{
			name:  "ipv6",
			rules: [][3]any{{"wide", "2001:db8::/32", 3}, {"net", "2001:db8:1::/48", 1}},
			want: map[string][]string{
				"2001:db8::/32":   {"wide"},
				"2001:db8:1::/48": {"net", "wide"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rules []*rule
			for _, r := range tt.rules {
				rules = append(rules, parsedRule(t, r[0].(string), r[1].(string), uint32(r[2].(int))))
			}
			out, err := flattenRules(rules)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string][]string{}
			for p, rs := range out {
				for _, r := range rs {
					got[p.String()] = append(got[p.String()], r.id)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("flatten = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFlattenRulesPerDstLimit(t *testing.T) {
	build := func(n int) []*rule {
		var rules []*rule
		for i := 0; i < n; i++ {
			rules = append(rules, parsedRule(t, fmt.Sprintf("r%02d", i), "10.0.0.1/32", 1))
		}
		return rules
	}
	if _, err := flattenRules(build(ebpf.RulesPerDst)); err != nil {
		t.Fatalf("%d rules on one destination: %v", ebpf.RulesPerDst, err)
	}
	if _, err := flattenRules(build(ebpf.RulesPerDst + 1)); err == nil {
		t.Fatalf("%d rules on one destination accepted", ebpf.RulesPerDst+1)
	}
}

func TestRuleTriesPerFamily(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)
	res := mustApply(t, e, upsert(
		testRule("v4wide", "10.0.0.0/16", 1),
		testRule("v4host", "10.0.1.1/32", 2),
		testRule("v6", "2001:db8::/32", 1),
	), ruleT0)
	if res.Upserted != 3 || res.ActiveV4 != 2 || res.ActiveV6 != 1 {
		t.Fatalf("result = %+v", res)
	}
	wide, host, v6 := slotOf(t, e, "v4wide"), slotOf(t, e, "v4host"), slotOf(t, e, "v6")
	want4 := map[netip.Prefix][]uint16{
		netip.MustParsePrefix("10.0.0.0/16"): {wide},
		netip.MustParsePrefix("10.0.1.1/32"): {wide, host},
	}
	want6 := map[netip.Prefix][]uint16{netip.MustParsePrefix("2001:db8::/32"): {v6}}
	if !reflect.DeepEqual(f.tries[0], want4) {
		t.Errorf("v4 trie = %v, want %v", f.tries[0], want4)
	}
	if !reflect.DeepEqual(f.tries[1], want6) {
		t.Errorf("v6 trie = %v, want %v", f.tries[1], want6)
	}
}

func TestRuleSlotReuse(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)

	mustApply(t, e, upsert(testRule("a", "192.0.2.0/24", 1)), ruleT0)
	slotA := slotOf(t, e, "a")
	if !slices.Equal(f.puts, []uint16{slotA}) || !slices.Equal(f.resets, []uint16{slotA}) {
		t.Fatalf("first install: puts %v resets %v", f.puts, f.resets)
	}

	t.Run("unchanged rule keeps slot without rewrite", func(t *testing.T) {
		puts, resets := len(f.puts), len(f.resets)
		mustApply(t, e, upsert(testRule("a", "192.0.2.0/24", 1)), ruleT0)
		if got := slotOf(t, e, "a"); got != slotA {
			t.Fatalf("slot = %d, want %d", got, slotA)
		}
		if len(f.puts) != puts || len(f.resets) != resets {
			t.Fatalf("unchanged rule rewritten: puts %v resets %v", f.puts, f.resets)
		}
	})

	var slotA2 uint16
	t.Run("changed rule gets new slot with reset bucket", func(t *testing.T) {
		mustApply(t, e, upsert(testRule("a", "192.0.2.0/24", 1, func(r *apiv1.Rule) { r.Protocols = []uint32{17} })), ruleT0)
		slotA2 = slotOf(t, e, "a")
		if slotA2 == slotA {
			t.Fatalf("changed rule kept slot %d", slotA)
		}
		if f.puts[len(f.puts)-1] != slotA2 || f.resets[len(f.resets)-1] != slotA2 {
			t.Fatalf("new slot %d not written/reset: puts %v resets %v", slotA2, f.puts, f.resets)
		}
	})

	t.Run("retired slot held during grace", func(t *testing.T) {
		mustApply(t, e, upsert(testRule("b", "198.51.100.0/24", 1)), ruleT0.Add(slotGrace-time.Millisecond))
		if s := slotOf(t, e, "b"); s == slotA || s == slotA2 {
			t.Fatalf("b got slot %d during grace (a was %d, now %d)", s, slotA, slotA2)
		}
	})

	t.Run("retired slot reused after grace", func(t *testing.T) {
		mustApply(t, e, upsert(testRule("c", "203.0.113.0/24", 1)), ruleT0.Add(slotGrace))
		if s := slotOf(t, e, "c"); s != slotA {
			t.Fatalf("c got slot %d, want released slot %d", s, slotA)
		}
	})
}

func TestRuleRemovedSlotHeldDuringGrace(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)
	mustApply(t, e, upsert(testRule("a", "192.0.2.0/24", 1)), ruleT0)
	slotA := slotOf(t, e, "a")

	res := mustApply(t, e, &apiv1.RuleSetDelta{Remove: []string{"a", "unknown"}}, ruleT0)
	if res.Removed != 1 {
		t.Fatalf("Removed = %d, want 1", res.Removed)
	}
	if len(f.tries[0]) != 0 {
		t.Fatalf("v4 trie after remove = %v", f.tries[0])
	}
	mustApply(t, e, upsert(testRule("b", "192.0.2.0/24", 1)), ruleT0.Add(slotGrace/2))
	if slotOf(t, e, "b") == slotA {
		t.Fatalf("removed slot %d reused within grace", slotA)
	}
	mustApply(t, e, upsert(testRule("c", "198.51.100.0/24", 1)), ruleT0.Add(slotGrace))
	if s := slotOf(t, e, "c"); s != slotA {
		t.Fatalf("c got slot %d, want released slot %d", s, slotA)
	}
}

func TestRuleRemoveUnknownIsNoop(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)
	mustApply(t, e, upsert(testRule("a", "192.0.2.0/24", 1)), ruleT0)
	puts := len(f.puts)
	res := mustApply(t, e, &apiv1.RuleSetDelta{Remove: []string{"ghost"}}, ruleT0)
	if res.Removed != 0 || res.ActiveV4 != 1 {
		t.Fatalf("result = %+v", res)
	}
	if got := ruleIDs(e); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("rules = %v", got)
	}
	if len(f.puts) != puts {
		t.Fatalf("remove of unknown id wrote rule bodies")
	}
}

func TestRuleExpire(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)
	exp := func(d time.Duration) func(*apiv1.Rule) {
		return func(r *apiv1.Rule) { r.ExpiresAt = timestamppb.New(ruleT0.Add(d)) }
	}
	mustApply(t, e, upsert(
		testRule("z-early", "192.0.2.0/24", 1, exp(10*time.Second)),
		testRule("a-early", "2001:db8::/32", 1, exp(5*time.Second)),
		testRule("late", "198.51.100.0/24", 1, exp(time.Minute)),
	), ruleT0)
	lateSlot := slotOf(t, e, "late")

	got, err := e.Expire(ruleT0.Add(time.Second))
	if err != nil || len(got) != 0 {
		t.Fatalf("Expire before any expiry = %v, %v", got, err)
	}

	got, err = e.Expire(ruleT0.Add(10 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a-early", "z-early"}; !slices.Equal(got, want) {
		t.Fatalf("expired = %v, want %v", got, want)
	}
	if ids := ruleIDs(e); !slices.Equal(ids, []string{"late"}) {
		t.Fatalf("remaining rules = %v", ids)
	}
	want4 := map[netip.Prefix][]uint16{netip.MustParsePrefix("198.51.100.0/24"): {lateSlot}}
	if !reflect.DeepEqual(f.tries[0], want4) {
		t.Errorf("v4 trie = %v, want %v", f.tries[0], want4)
	}
	if len(f.tries[1]) != 0 {
		t.Errorf("v6 trie = %v, want empty", f.tries[1])
	}
}

func TestRuleSwapFailureRestoresIPv4(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)
	mustApply(t, e, upsert(testRule("a", "192.0.2.0/24", 1)), ruleT0)
	prev4 := f.tries[0]
	v4Swaps := len(f.swaps[0])

	f.swapErr[1] = errors.New("v6 swap failed")
	_, err := e.Apply(upsert(testRule("b", "198.51.100.0/24", 1), testRule("c", "2001:db8::/32", 1)), ruleT0)
	if err == nil || !strings.Contains(err.Error(), "v6 swap failed") {
		t.Fatalf("Apply error = %v", err)
	}
	if ids := ruleIDs(e); !slices.Equal(ids, []string{"a"}) {
		t.Fatalf("engine rules = %v, want [a]", ids)
	}
	swaps := f.swaps[0][v4Swaps:]
	if len(swaps) != 2 {
		t.Fatalf("v4 swaps after failure = %d, want new set then restore", len(swaps))
	}
	if !reflect.DeepEqual(f.tries[0], prev4) {
		t.Fatalf("v4 trie = %v, want restored %v", f.tries[0], prev4)
	}
}

func TestRuleRestoreFailureRetiresFreshSlots(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)
	mustApply(t, e, upsert(testRule("a", "192.0.2.0/24", 1)), ruleT0)
	v4Calls := f.calls[0]

	// The new IPv4 trie installs, IPv6 fails, and restoring IPv4 fails too.
	f.swapFail = func(fam, call int) error {
		if fam == 1 || call > v4Calls+1 {
			return errors.New("swap failed")
		}
		return nil
	}
	if _, err := e.Apply(upsert(testRule("b", "198.51.100.0/24", 1), testRule("c", "2001:db8::/32", 1)), ruleT0); err == nil {
		t.Fatal("Apply succeeded")
	}
	f.swapFail = nil

	// The live IPv4 trie may still reference b's slot: it must not be free
	// for reuse before the grace period.
	for _, slots := range f.tries[0] {
		for _, s := range slots {
			if slices.Contains(e.free, s) {
				t.Fatalf("slot %d is free while the live IPv4 trie still references it", s)
			}
		}
	}
}

func TestRulePutFailureCommitsNothing(t *testing.T) {
	f := newFakeRuleMaps()
	e := newRuleEngine(f)
	mustApply(t, e, upsert(testRule("a", "192.0.2.0/24", 1)), ruleT0)
	before := f.snapshot()
	freeBefore := len(e.free)

	f.putErr = errors.New("put failed")
	if _, err := e.Apply(upsert(testRule("b", "198.51.100.0/24", 1)), ruleT0); err == nil {
		t.Fatal("Apply succeeded despite PutRuleBody failure")
	}
	assertUnchanged(t, e, f, before, []string{"a"})
	if len(e.free) != freeBefore {
		t.Errorf("free slots = %d, want %d", len(e.free), freeBefore)
	}
}

func TestRuleParseBody(t *testing.T) {
	tests := []struct {
		name  string
		rule  *apiv1.Rule
		check func(t *testing.T, b ebpf.ScrubRule)
	}{
		{"no protocols means any", testRule("r", "192.0.2.0/24", 1), func(t *testing.T, b ebpf.ScrubRule) {
			if b.AnyProto != 1 || b.ProtoBits != [4]uint64{} {
				t.Fatalf("AnyProto %d ProtoBits %x", b.AnyProto, b.ProtoBits)
			}
		}},
		{"protocol bits", testRule("r", "192.0.2.0/24", 1, func(r *apiv1.Rule) { r.Protocols = []uint32{6, 17, 64, 255} }), func(t *testing.T, b ebpf.ScrubRule) {
			want := [4]uint64{1<<6 | 1<<17, 1, 0, 1 << 63}
			if b.AnyProto != 0 || b.ProtoBits != want {
				t.Fatalf("AnyProto %d ProtoBits %x, want %x", b.AnyProto, b.ProtoBits, want)
			}
		}},
		{"fragment unset", testRule("r", "192.0.2.0/24", 1), func(t *testing.T, b ebpf.ScrubRule) {
			if b.Fragment != ebpf.RuleFragAny {
				t.Fatalf("Fragment = %d", b.Fragment)
			}
		}},
		{"fragment true", testRule("r", "192.0.2.0/24", 1, func(r *apiv1.Rule) { r.Fragment = proto.Bool(true) }), func(t *testing.T, b ebpf.ScrubRule) {
			if b.Fragment != ebpf.RuleFragOnly {
				t.Fatalf("Fragment = %d", b.Fragment)
			}
		}},
		{"fragment false", testRule("r", "192.0.2.0/24", 1, func(r *apiv1.Rule) { r.Fragment = proto.Bool(false) }), func(t *testing.T, b ebpf.ScrubRule) {
			if b.Fragment != ebpf.RuleFragNone {
				t.Fatalf("Fragment = %d", b.Fragment)
			}
		}},
		{"v4 source masked", testRule("r", "192.0.2.0/24", 1, func(r *apiv1.Rule) { r.SrcPrefixes = []string{"198.51.100.77/24"} }), func(t *testing.T, b ebpf.ScrubRule) {
			var addr, mask [16]byte
			copy(addr[:], []byte{198, 51, 100, 0})
			copy(mask[:], []byte{0xff, 0xff, 0xff, 0})
			if b.NSources != 1 || b.Sources[0] != (ebpf.RulePrefix{Addr: addr, Mask: mask}) {
				t.Fatalf("NSources %d Sources[0] %+v", b.NSources, b.Sources[0])
			}
		}},
		{"v6 source masked", testRule("r", "2001:db8::/32", 1, func(r *apiv1.Rule) { r.SrcPrefixes = []string{"2001:db8:abcd:1234::1/48"} }), func(t *testing.T, b ebpf.ScrubRule) {
			addr := netip.MustParseAddr("2001:db8:abcd::").As16()
			var mask [16]byte
			copy(mask[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
			if b.NSources != 1 || b.Sources[0] != (ebpf.RulePrefix{Addr: addr, Mask: mask}) {
				t.Fatalf("NSources %d Sources[0] %+v", b.NSources, b.Sources[0])
			}
		}},
		{"ports, length and flags", testRule("r", "192.0.2.0/24", 1, func(r *apiv1.Rule) {
			r.SrcPorts = []*apiv1.PortRange{{From: 1024, To: 65535}}
			r.DstPorts = []*apiv1.PortRange{{From: 53, To: 53}, {From: 123, To: 123}}
			r.PktLen = &apiv1.PortRange{From: 40, To: 60}
			r.TcpFlagsMask, r.TcpFlagsValue = 0x12, 0x02
			r.Action = apiv1.RuleAction_RULE_ACTION_PASS
		}), func(t *testing.T, b ebpf.ScrubRule) {
			if b.NSrcPorts != 1 || b.SrcPorts[0] != (ebpf.RuleRange{From: 1024, To: 65535}) {
				t.Errorf("src ports %d %+v", b.NSrcPorts, b.SrcPorts[0])
			}
			if b.NDstPorts != 2 || b.DstPorts[1] != (ebpf.RuleRange{From: 123, To: 123}) {
				t.Errorf("dst ports %d %+v", b.NDstPorts, b.DstPorts[:2])
			}
			if b.LenFrom != 40 || b.LenTo != 60 || b.TCPFlagsMask != 0x12 || b.TCPFlagsValue != 0x02 || b.Action != ebpf.RuleActionPass {
				t.Errorf("body %+v", b)
			}
		}},
		{"rate limit", testRule("r", "192.0.2.0/24", 1, func(r *apiv1.Rule) {
			r.Action, r.RatePps = apiv1.RuleAction_RULE_ACTION_RATE_LIMIT, 5000
		}), func(t *testing.T, b ebpf.ScrubRule) {
			if b.Action != ebpf.RuleActionRateLimit || b.RateWindowNS != uint64(100*time.Millisecond) || b.RateBudget != 500 {
				t.Fatalf("action %d window %d budget %d", b.Action, b.RateWindowNS, b.RateBudget)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parseRule(tt.rule, ruleT0)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, r.body)
		})
	}
}

func TestRuleParseMasksDst(t *testing.T) {
	r, err := parseRule(testRule("r", "192.0.2.77/24", 1), ruleT0)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParsePrefix("192.0.2.0/24"); r.dst != want {
		t.Fatalf("dst = %s, want %s", r.dst, want)
	}
}

func TestRateWindow(t *testing.T) {
	tests := []struct {
		pps        uint64
		window     time.Duration
		wantBudget uint64
	}{
		{1, time.Second, 1},
		{50, time.Second, 50},
		{99, time.Second, 99},
		{100, 100 * time.Millisecond, 10},
		{105, 100 * time.Millisecond, 10},
		{1_000_000, 100 * time.Millisecond, 100_000},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.pps), func(t *testing.T) {
			w, b := rateWindow(tt.pps)
			if w != uint64(tt.window) || b != tt.wantBudget {
				t.Fatalf("rateWindow(%d) = %d, %d; want %d, %d", tt.pps, w, b, tt.window, tt.wantBudget)
			}
			if b == 0 {
				t.Fatal("zero budget")
			}
		})
	}
}

func TestRuleEncodingForBinarySearch(t *testing.T) {
	pr := testRule("r", "192.0.2.0/24", 1, func(r *apiv1.Rule) {
		r.Protocols = []uint32{6}
		r.DstPorts = []*apiv1.PortRange{{From: 500, To: 600}, {From: 80, To: 80}, {From: 550, To: 700}, {From: 81, To: 90}, {From: 1000, To: 1000}}
		r.SrcPrefixes = []string{"10.0.0.9/32", "10.0.0.3/32", "10.0.0.3/32", "10.0.0.7/32"}
	})
	r, err := parseRule(pr, ruleT0)
	if err != nil {
		t.Fatal(err)
	}
	b := r.body
	wantPorts := []ebpf.RuleRange{{From: 80, To: 90}, {From: 500, To: 700}, {From: 1000, To: 1000}}
	if got := b.DstPorts[:b.NDstPorts]; !slices.Equal(got, wantPorts) {
		t.Errorf("dst ports = %v, want sorted and merged %v", got, wantPorts)
	}
	if b.NSources != 3 || b.SrcBsearch != 1 {
		t.Fatalf("sources = %d, bsearch = %d; want 3 deduplicated same-length sources", b.NSources, b.SrcBsearch)
	}
	for i, want := range []byte{3, 7, 9} {
		if got := b.Sources[i].Addr[3]; got != want {
			t.Errorf("source %d = .%d, want .%d", i, got, want)
		}
	}
	if b.SrcLo != 0x0a000003 || b.SrcHi != 0x0a000009 {
		t.Errorf("span = %08x-%08x, want 0a000003-0a000009", b.SrcLo, b.SrcHi)
	}

	mixed, err := parseRule(testRule("m", "192.0.2.0/24", 1, func(r *apiv1.Rule) {
		r.SrcPrefixes = []string{"10.0.1.0/24", "10.0.0.8/29", "0.0.0.0/0"}
	}), ruleT0)
	if err != nil {
		t.Fatal(err)
	}
	if mb := mixed.body; mb.SrcBsearch != 0 || mb.SrcLo != 0 || mb.SrcHi != math.MaxUint32 {
		t.Errorf("mixed lengths: bsearch=%d span=%08x-%08x, want linear walk over the whole space", mb.SrcBsearch, mb.SrcLo, mb.SrcHi)
	}

	v6, err := parseRule(testRule("v6", "2001:db8::/32", 1, func(r *apiv1.Rule) {
		r.SrcPrefixes = []string{"2001:db8:1::/48"}
	}), ruleT0)
	if err != nil {
		t.Fatal(err)
	}
	if v6.body.SrcBsearch != 0 {
		t.Error("IPv6 sources must use the linear walk")
	}
}
