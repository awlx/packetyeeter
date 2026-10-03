// Package scrubrules validates scrub-mode runtime rules and lays them out for
// the XDP matcher. The analyzer uses it to reject a rule set before sending
// it; scrub collectors use it to build what they install.
package scrubrules

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"
)

// Rule is a validated rule with its kernel encoding.
type Rule struct {
	ID       string
	Priority uint32
	Dst      netip.Prefix
	Expires  time.Time
	Body     ebpf.ScrubRule
}

// CheckCapacity reports whether rules fit the XDP matcher's limits.
func CheckCapacity(rules map[string]*Rule) error {
	v4, v6 := SplitFamilies(rules)
	if len(v4) > ebpf.RulesMax || len(v6) > ebpf.RulesMax {
		return fmt.Errorf("too many rules: %d IPv4, %d IPv6 (at most %d per family)", len(v4), len(v6), ebpf.RulesMax)
	}
	if _, err := Flatten(v4); err != nil {
		return err
	}
	_, err := Flatten(v6)
	return err
}

func SplitFamilies(rules map[string]*Rule) (v4, v6 []*Rule) {
	for _, r := range rules {
		if r.Dst.Addr().Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	return v4, v6
}

// Flatten returns, for each distinct destination prefix, every rule
// whose prefix covers it, in evaluation order. The kernel only sees the
// longest-prefix match, so a /24 rule with a lower priority than a /32 rule
// must also be listed under the /32.
func Flatten(rules []*Rule) (map[netip.Prefix][]*Rule, error) {
	byPrefix := map[netip.Prefix][]*Rule{}
	for _, r := range rules {
		byPrefix[r.Dst] = append(byPrefix[r.Dst], r)
	}
	out := make(map[netip.Prefix][]*Rule, len(byPrefix))
	for p := range byPrefix {
		// Walking p's ancestors keeps this linear in the number of prefixes.
		var covering []*Rule
		for bits := 0; bits <= p.Bits(); bits++ {
			ancestor, _ := p.Addr().Prefix(bits)
			covering = append(covering, byPrefix[ancestor]...)
		}
		slices.SortFunc(covering, func(a, b *Rule) int {
			return cmp.Or(cmp.Compare(a.Priority, b.Priority), cmp.Compare(a.ID, b.ID))
		})
		if len(covering) > ebpf.RulesPerDst {
			return nil, fmt.Errorf("destination %s would be covered by %d rules, at most %d", p, len(covering), ebpf.RulesPerDst)
		}
		out[p] = covering
	}
	return out, nil
}

func Parse(pr *apiv1.Rule, now time.Time) (*Rule, error) {
	r := &Rule{ID: pr.GetId(), Priority: pr.GetPriority()}
	if r.ID == "" {
		return nil, errors.New("rule without id")
	}
	fail := func(format string, args ...any) (*Rule, error) {
		return nil, fmt.Errorf("rule %q: %s", r.ID, fmt.Sprintf(format, args...))
	}

	dst, err := netip.ParsePrefix(pr.GetDstPrefix())
	if err != nil {
		return fail("dst_prefix: %v", err)
	}
	r.Dst = dst.Masked()
	v4 := r.Dst.Addr().Is4()

	if pr.GetExpiresAt() == nil {
		return fail("expires_at is required")
	}
	r.Expires = pr.GetExpiresAt().AsTime()
	if !now.Before(r.Expires) {
		return fail("already expired at %s", r.Expires.Format(time.RFC3339))
	}

	b := &r.Body
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
		b.RateWindowNS, b.RateBudget = RateWindow(pr.GetRatePps())
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
	for i, s := range pr.GetSrcPrefixes() {
		src, err := netip.ParsePrefix(s)
		if err != nil {
			return fail("src_prefixes: %v", err)
		}
		if src.Addr().Is4() != v4 {
			return fail("src_prefixes %s is not the same address family as dst_prefix", s)
		}
		b.Sources[i] = rulePrefix(src.Masked())
	}
	b.NSources = uint8(len(pr.GetSrcPrefixes()))
	return r, nil
}

func portRanges(dst []ebpf.RuleRange, in []*apiv1.PortRange) (uint8, error) {
	if len(in) > len(dst) {
		return 0, fmt.Errorf("%d ranges, at most %d", len(in), len(dst))
	}
	for i, pr := range in {
		if pr.GetFrom() > pr.GetTo() || pr.GetTo() > 65535 {
			return 0, fmt.Errorf("%d-%d is not a valid port range", pr.GetFrom(), pr.GetTo())
		}
		dst[i] = ebpf.RuleRange{From: uint16(pr.GetFrom()), To: uint16(pr.GetTo())}
	}
	return uint8(len(in)), nil
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

// RateWindow uses 100ms windows for smooth pacing, and 1s below 100 pps so a
// small rate is not rounded down to zero packets per window.
func RateWindow(pps uint64) (windowNS, budget uint64) {
	if pps < 100 {
		return uint64(time.Second), pps
	}
	return uint64(100 * time.Millisecond), pps / 10
}
