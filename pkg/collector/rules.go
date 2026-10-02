package collector

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"

	"github.com/sirupsen/logrus"
)

// ruleMaps is the kernel side of the rule engine, faked in tests.
type ruleMaps interface {
	PutRuleBody(slot uint16, rule *ebpf.ScrubRule) error
	ResetRuleBucket(slot uint16) error
	SwapRuleTrie(v6 bool, entries map[netip.Prefix][]uint16) error
}

// slotGrace is how long a replaced rule body stays reserved. XDP readers of
// the previous trie finish within microseconds; this only has to outlast them.
const slotGrace = time.Second

type rule struct {
	id       string
	priority uint32
	dst      netip.Prefix
	expires  time.Time
	body     ebpf.ScrubRule
}

type installedRule struct {
	slot uint16
	body ebpf.ScrubRule
}

type retiredSlot struct {
	slot uint16
	at   time.Time
}

// ruleEngine owns the scrub-mode runtime rules: it applies deltas
// all-or-nothing, expires rules, and keeps the kernel tries in sync.
type ruleEngine struct {
	mu        sync.Mutex
	maps      ruleMaps
	rules     map[string]*rule
	installed map[string]installedRule
	free      []uint16
	retired   []retiredSlot

	// Read by metrics scrapes, which must not wait for a rebuild.
	activeV4, activeV6 atomic.Int64
}

func newRuleEngine(m ruleMaps) *ruleEngine {
	e := &ruleEngine{
		maps:      m,
		rules:     map[string]*rule{},
		installed: map[string]installedRule{},
		free:      make([]uint16, 0, ebpf.RuleSlots),
	}
	for s := ebpf.RuleSlots - 1; s >= 0; s-- {
		e.free = append(e.free, uint16(s))
	}
	return e
}

type ruleApplyResult struct {
	Upserted, Removed  int
	ActiveV4, ActiveV6 int
}

// Apply validates the whole delta before changing anything; one bad rule
// rejects all of it.
func (e *ruleEngine) Apply(delta *apiv1.RuleSetDelta, now time.Time) (ruleApplyResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	next := maps.Clone(e.rules)
	removed := 0
	for _, id := range delta.GetRemove() {
		if _, ok := next[id]; ok {
			delete(next, id)
			removed++
		}
	}
	seen := map[string]bool{}
	for _, pr := range delta.GetUpsert() {
		r, err := parseRule(pr, now)
		if err != nil {
			return ruleApplyResult{}, err
		}
		if seen[r.id] {
			return ruleApplyResult{}, fmt.Errorf("rule %q appears twice in one delta", r.id)
		}
		seen[r.id] = true
		next[r.id] = r
	}
	if err := e.install(next, now); err != nil {
		return ruleApplyResult{}, err
	}
	res := ruleApplyResult{Upserted: len(seen), Removed: removed}
	res.ActiveV4, res.ActiveV6 = e.Counts()
	return res, nil
}

// Expire removes rules whose expiry has passed and returns their ids.
func (e *ruleEngine) Expire(now time.Time) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var expired []string
	for id, r := range e.rules {
		if !now.Before(r.expires) {
			expired = append(expired, id)
		}
	}
	if len(expired) == 0 {
		e.releaseRetired(now)
		return nil, nil
	}
	next := maps.Clone(e.rules)
	for _, id := range expired {
		delete(next, id)
	}
	if err := e.install(next, now); err != nil {
		return nil, err
	}
	slices.Sort(expired)
	return expired, nil
}

func (e *ruleEngine) Counts() (v4, v6 int) {
	return int(e.activeV4.Load()), int(e.activeV6.Load())
}

// install makes next the active rule set. On error the kernel keeps the
// previous tries and e.rules is unchanged.
func (e *ruleEngine) install(next map[string]*rule, now time.Time) error {
	e.releaseRetired(now)

	v4, v6 := splitFamilies(next)
	if len(v4) > ebpf.RulesMax || len(v6) > ebpf.RulesMax {
		return fmt.Errorf("too many rules: %d IPv4, %d IPv6 (at most %d per family)", len(v4), len(v6), ebpf.RulesMax)
	}
	entries4, err := flattenRules(v4)
	if err != nil {
		return err
	}
	entries6, err := flattenRules(v6)
	if err != nil {
		return err
	}

	// Unchanged rules keep their slot, and with it their rate-limit window.
	slots := make(map[string]uint16, len(next))
	var fresh []uint16
	rollback := func() { e.free = append(e.free, fresh...) }
	for id, r := range next {
		if cur, ok := e.installed[id]; ok && cur.body == r.body {
			slots[id] = cur.slot
			continue
		}
		if len(e.free) == 0 {
			rollback()
			return errors.New("no free rule slots; retry once replaced rules are released")
		}
		slot := e.free[len(e.free)-1]
		e.free = e.free[:len(e.free)-1]
		fresh = append(fresh, slot)
		if err := e.maps.PutRuleBody(slot, &r.body); err != nil {
			rollback()
			return fmt.Errorf("write rule %q: %w", id, err)
		}
		if err := e.maps.ResetRuleBucket(slot); err != nil {
			rollback()
			return fmt.Errorf("reset rate limit of rule %q: %w", id, err)
		}
		slots[id] = slot
	}

	// Each family's trie is swapped in one map update; a packet is only ever
	// matched against one family.
	if err := e.maps.SwapRuleTrie(false, slotEntries(entries4, slots)); err != nil {
		rollback()
		return err
	}
	if err := e.maps.SwapRuleTrie(true, slotEntries(entries6, slots)); err != nil {
		// Put the previous IPv4 rules back. If that fails too, the next
		// successful install rebuilds both tries from scratch.
		old4, _ := splitFamilies(e.rules)
		prev, ferr := flattenRules(old4)
		if ferr == nil {
			ferr = e.maps.SwapRuleTrie(false, slotEntries(prev, e.installedSlots()))
		}
		if ferr != nil {
			// The live IPv4 trie may still point at the fresh slots, so they
			// must not be handed out again before the grace period.
			for _, slot := range fresh {
				e.retired = append(e.retired, retiredSlot{slot: slot, at: now})
			}
			return fmt.Errorf("%w (restoring the previous IPv4 rules also failed: %v)", err, ferr)
		}
		rollback()
		return err
	}
	e.commit(next, slots, now)
	return nil
}

func (e *ruleEngine) installedSlots() map[string]uint16 {
	out := make(map[string]uint16, len(e.installed))
	for id, ir := range e.installed {
		out[id] = ir.slot
	}
	return out
}

func (e *ruleEngine) commit(next map[string]*rule, slots map[string]uint16, now time.Time) {
	installed := make(map[string]installedRule, len(next))
	for id, r := range next {
		installed[id] = installedRule{slot: slots[id], body: r.body}
	}
	for id, cur := range e.installed {
		if n, ok := installed[id]; !ok || n.slot != cur.slot {
			e.retired = append(e.retired, retiredSlot{slot: cur.slot, at: now})
		}
	}
	e.installed = installed
	e.rules = next
	v4, v6 := splitFamilies(next)
	e.activeV4.Store(int64(len(v4)))
	e.activeV6.Store(int64(len(v6)))
}

func (e *ruleEngine) releaseRetired(now time.Time) {
	kept := e.retired[:0]
	for _, r := range e.retired {
		if now.Sub(r.at) >= slotGrace {
			e.free = append(e.free, r.slot)
		} else {
			kept = append(kept, r)
		}
	}
	e.retired = kept
}

func splitFamilies(rules map[string]*rule) (v4, v6 []*rule) {
	for _, r := range rules {
		if r.dst.Addr().Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	return v4, v6
}

// flattenRules returns, for each distinct destination prefix, every rule
// whose prefix covers it, in evaluation order. The kernel only sees the
// longest-prefix match, so a /24 rule with a lower priority than a /32 rule
// must also be listed under the /32.
func flattenRules(rules []*rule) (map[netip.Prefix][]*rule, error) {
	byPrefix := map[netip.Prefix][]*rule{}
	for _, r := range rules {
		byPrefix[r.dst] = append(byPrefix[r.dst], r)
	}
	out := make(map[netip.Prefix][]*rule, len(byPrefix))
	for p := range byPrefix {
		// Walking p's ancestors keeps this linear in the number of prefixes.
		var covering []*rule
		for bits := 0; bits <= p.Bits(); bits++ {
			ancestor, _ := p.Addr().Prefix(bits)
			covering = append(covering, byPrefix[ancestor]...)
		}
		slices.SortFunc(covering, func(a, b *rule) int {
			return cmp.Or(cmp.Compare(a.priority, b.priority), cmp.Compare(a.id, b.id))
		})
		if len(covering) > ebpf.RulesPerDst {
			return nil, fmt.Errorf("destination %s would be covered by %d rules, at most %d", p, len(covering), ebpf.RulesPerDst)
		}
		out[p] = covering
	}
	return out, nil
}

func slotEntries(entries map[netip.Prefix][]*rule, slots map[string]uint16) map[netip.Prefix][]uint16 {
	out := make(map[netip.Prefix][]uint16, len(entries))
	for p, rules := range entries {
		s := make([]uint16, len(rules))
		for i, r := range rules {
			s[i] = slots[r.id]
		}
		out[p] = s
	}
	return out
}

func parseRule(pr *apiv1.Rule, now time.Time) (*rule, error) {
	r := &rule{id: pr.GetId(), priority: pr.GetPriority()}
	if r.id == "" {
		return nil, errors.New("rule without id")
	}
	fail := func(format string, args ...any) (*rule, error) {
		return nil, fmt.Errorf("rule %q: %s", r.id, fmt.Sprintf(format, args...))
	}

	dst, err := netip.ParsePrefix(pr.GetDstPrefix())
	if err != nil {
		return fail("dst_prefix: %v", err)
	}
	r.dst = dst.Masked()
	v4 := r.dst.Addr().Is4()

	if pr.GetExpiresAt() == nil {
		return fail("expires_at is required")
	}
	r.expires = pr.GetExpiresAt().AsTime()
	if !now.Before(r.expires) {
		return fail("already expired at %s", r.expires.Format(time.RFC3339))
	}

	b := &r.body
	switch pr.GetAction() {
	case apiv1.RuleAction_RULE_ACTION_DROP:
		b.Action = ebpf.RuleActionDrop
	case apiv1.RuleAction_RULE_ACTION_PASS:
		b.Action = ebpf.RuleActionPass
	case apiv1.RuleAction_RULE_ACTION_RATE_LIMIT:
		if pr.GetRatePps() == 0 {
			return fail("rate_limit needs rate_pps > 0")
		}
		b.Action = ebpf.RuleActionRateLimit
		b.RateWindowNS, b.RateBudget = rateWindow(pr.GetRatePps())
	default:
		return fail("unsupported action %v", pr.GetAction())
	}
	if pr.GetRatePps() != 0 && b.Action != ebpf.RuleActionRateLimit {
		return fail("rate_pps is only valid with RULE_ACTION_RATE_LIMIT")
	}

	// Conditions the protocols rule out could never match; reject them
	// rather than install a rule that silently does nothing.
	allows := func(proto uint32) bool {
		return len(pr.GetProtocols()) == 0 || slices.Contains(pr.GetProtocols(), proto)
	}
	if (len(pr.GetSrcPorts()) > 0 || len(pr.GetDstPorts()) > 0) && !allows(6) && !allows(17) {
		return fail("port ranges need protocol 6 (TCP) or 17 (UDP)")
	}
	if pr.GetTcpFlagsMask() != 0 && !allows(6) {
		return fail("tcp flags need protocol 6 (TCP)")
	}

	if len(pr.GetProtocols()) == 0 {
		b.AnyProto = 1
	}
	for _, p := range pr.GetProtocols() {
		if p > 255 {
			return fail("protocol %d out of range", p)
		}
		b.ProtoBits[p/64] |= 1 << (p % 64)
	}

	if b.NSrcPorts, err = portRanges(b.SrcPorts[:], pr.GetSrcPorts()); err != nil {
		return fail("src_ports: %v", err)
	}
	if b.NDstPorts, err = portRanges(b.DstPorts[:], pr.GetDstPorts()); err != nil {
		return fail("dst_ports: %v", err)
	}

	if l := pr.GetPktLen(); l != nil && (l.GetFrom() != 0 || l.GetTo() != 0) {
		if l.GetFrom() > l.GetTo() || l.GetTo() > 65535 || l.GetTo() == 0 {
			return fail("pkt_len %d-%d is not a valid range", l.GetFrom(), l.GetTo())
		}
		b.LenFrom, b.LenTo = uint16(l.GetFrom()), uint16(l.GetTo())
	}

	if pr.GetTcpFlagsMask() > 255 || pr.GetTcpFlagsValue() > 255 {
		return fail("tcp flags must fit in 8 bits")
	}
	if pr.GetTcpFlagsValue()&^pr.GetTcpFlagsMask() != 0 {
		return fail("tcp_flags_value sets bits outside tcp_flags_mask")
	}
	b.TCPFlagsMask, b.TCPFlagsValue = uint8(pr.GetTcpFlagsMask()), uint8(pr.GetTcpFlagsValue())

	if pr.Fragment != nil {
		b.Fragment = ebpf.RuleFragNone
		if pr.GetFragment() {
			b.Fragment = ebpf.RuleFragOnly
		}
	}

	if len(pr.GetSrcPrefixes()) > ebpf.RuleMaxSources {
		return fail("%d src_prefixes, at most %d", len(pr.GetSrcPrefixes()), ebpf.RuleMaxSources)
	}
	srcs := make([]netip.Prefix, 0, len(pr.GetSrcPrefixes()))
	for _, s := range pr.GetSrcPrefixes() {
		src, err := netip.ParsePrefix(s)
		if err != nil {
			return fail("src_prefixes: %v", err)
		}
		if src.Addr().Is4() != v4 {
			return fail("src_prefixes %s is not the same address family as dst_prefix", s)
		}
		srcs = append(srcs, src.Masked())
	}
	encodeSources(b, srcs, v4)
	return r, nil
}

// encodeSources sorts IPv4 sources and records their span and whether they
// share one length, which lets XDP reject most packets with two compares and
// binary-search the rest.
func encodeSources(b *ebpf.ScrubRule, srcs []netip.Prefix, v4 bool) {
	if v4 {
		slices.SortFunc(srcs, func(x, y netip.Prefix) int { return x.Addr().Compare(y.Addr()) })
		srcs = slices.Compact(srcs)
	}
	for i, p := range srcs {
		b.Sources[i] = rulePrefix(p)
	}
	b.NSources = uint8(len(srcs))
	if !v4 || len(srcs) == 0 {
		return
	}
	b.SrcBsearch = 1
	b.SrcLo = math.MaxUint32
	for _, p := range srcs {
		if p.Bits() != srcs[0].Bits() {
			b.SrcBsearch = 0
		}
		start := binary.BigEndian.Uint32(p.Addr().AsSlice())
		end := start | uint32(math.MaxUint32>>p.Bits())
		if p.Bits() == 0 {
			end = math.MaxUint32
		}
		// The collector package shadows the max builtin.
		if start < b.SrcLo {
			b.SrcLo = start
		}
		if end > b.SrcHi {
			b.SrcHi = end
		}
	}
}

func portRanges(dst []ebpf.RuleRange, in []*apiv1.PortRange) (uint8, error) {
	if len(in) > len(dst) {
		return 0, fmt.Errorf("%d ranges, at most %d", len(in), len(dst))
	}
	ranges := make([]ebpf.RuleRange, 0, len(in))
	for _, pr := range in {
		if pr.GetFrom() > pr.GetTo() || pr.GetTo() > 65535 {
			return 0, fmt.Errorf("%d-%d is not a valid port range", pr.GetFrom(), pr.GetTo())
		}
		ranges = append(ranges, ebpf.RuleRange{From: uint16(pr.GetFrom()), To: uint16(pr.GetTo())})
	}
	// XDP binary-searches the ranges, so they must be sorted and disjoint.
	slices.SortFunc(ranges, func(x, y ebpf.RuleRange) int { return cmp.Compare(x.From, y.From) })
	n := 0
	for _, r := range ranges {
		if n > 0 && uint32(r.From) <= uint32(dst[n-1].To)+1 {
			if r.To > dst[n-1].To {
				dst[n-1].To = r.To
			}
			continue
		}
		dst[n] = r
		n++
	}
	return uint8(n), nil
}

func rulePrefix(p netip.Prefix) ebpf.RulePrefix {
	var out ebpf.RulePrefix
	addr := p.Addr().AsSlice()
	copy(out.Addr[:], addr)
	for i := 0; i < p.Bits(); i++ {
		out.Mask[i/8] |= 0x80 >> (i % 8)
	}
	return out
}

// rateWindow uses 100ms windows for smooth pacing, and 1s below 100 pps so a
// small rate is not rounded down to zero packets per window.
func rateWindow(pps uint64) (windowNS, budget uint64) {
	if pps < 100 {
		return uint64(time.Second), pps
	}
	return uint64(100 * time.Millisecond), pps / 10
}

func (c *Collector) applyRules(delta *apiv1.RuleSetDelta) {
	if c.rules == nil {
		c.Logger.Warn("Ignoring COMMAND_SET_RULES: runtime rules need -mode scrub")
		return
	}
	res, err := c.rules.Apply(delta, time.Now())
	if err != nil {
		c.Logger.WithError(err).WithFields(logrus.Fields{
			"upsert": len(delta.GetUpsert()),
			"remove": len(delta.GetRemove()),
		}).Warn("Rejected rule delta; previous rules stay active")
		return
	}
	c.Logger.WithFields(logrus.Fields{
		"upserted":  res.Upserted,
		"removed":   res.Removed,
		"active_v4": res.ActiveV4,
		"active_v6": res.ActiveV6,
	}).Info("Applied rule delta")
}

func (c *Collector) runRuleExpiry() {
	defer c.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			expired, err := c.rules.Expire(now)
			if err != nil {
				c.Logger.WithError(err).Warn("Failed to remove expired rules")
			}
			if len(expired) > 0 {
				c.Logger.WithField("rules", expired).Info("Removed expired rules")
			}
		}
	}
}
