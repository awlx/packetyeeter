package ebpf

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// Rule limits and layouts, mirroring the RULE_* #defines and structs in
// protector.bpf.c.
const (
	RulesMax       = 4096 // per family
	RuleSlots      = 16384
	RulesPerDst    = 32
	RuleMaxRanges  = 8
	RuleMaxSources = 8
)

// Rule actions, indexed like the rule_matches map.
const (
	RuleActionDrop      = 1
	RuleActionRateLimit = 2
	RuleActionPass      = 3
)

var RuleActionNames = map[uint8]string{
	RuleActionDrop:      "drop",
	RuleActionRateLimit: "rate_limit",
	RuleActionPass:      "pass",
}

const (
	RuleFragAny  = 0
	RuleFragOnly = 1
	RuleFragNone = 2
)

type RuleRange struct {
	From, To uint16
}

// RulePrefix holds a source prefix in network byte order, address pre-masked;
// IPv4 uses the first four bytes.
type RulePrefix struct {
	Addr [16]byte
	Mask [16]byte
}

// ScrubRule mirrors struct scrub_rule.
type ScrubRule struct {
	ProtoBits     [4]uint64
	RateWindowNS  uint64
	RateBudget    uint64
	Sources       [RuleMaxSources]RulePrefix
	SrcPorts      [RuleMaxRanges]RuleRange
	DstPorts      [RuleMaxRanges]RuleRange
	LenFrom       uint16
	LenTo         uint16
	Action        uint8
	AnyProto      uint8
	NSources      uint8
	NSrcPorts     uint8
	NDstPorts     uint8
	Fragment      uint8
	TCPFlagsMask  uint8
	TCPFlagsValue uint8
	Pad           [4]byte
}

// ruleList mirrors struct rule_list.
type ruleList struct {
	Count uint32
	Slots [RulesPerDst]uint16
}

type ruleBucket struct {
	Window uint64
	Count  uint64
}

func (m *Maps) PutRuleBody(slot uint16, rule *ScrubRule) error {
	if m.ScrubRules == nil {
		return errors.New("scrub_rules map not loaded")
	}
	return m.ScrubRules.Put(uint32(slot), rule)
}

// ResetRuleBucket gives a reused slot a fresh rate window.
func (m *Maps) ResetRuleBucket(slot uint16) error {
	if m.RuleBuckets == nil {
		return errors.New("rule_buckets map not loaded")
	}
	return m.RuleBuckets.Put(uint32(slot), ruleBucket{})
}

// SwapRuleTrie builds a new destination trie and installs it with a single
// outer-map update, so XDP sees either the old or the new rule set for the
// family, never a mix.
func (m *Maps) SwapRuleTrie(v6 bool, entries map[netip.Prefix][]uint16) error {
	outer, spec := m.RulesV4, m.RulesTrieSpecV4
	if v6 {
		outer, spec = m.RulesV6, m.RulesTrieSpecV6
	}
	if outer == nil || spec == nil {
		return errors.New("rules maps not loaded")
	}
	trie, err := ebpf.NewMap(spec)
	if err != nil {
		return fmt.Errorf("create rule trie: %w", err)
	}
	defer trie.Close()

	for prefix, slots := range entries {
		if len(slots) > RulesPerDst {
			return fmt.Errorf("%s: %d rules, at most %d", prefix, len(slots), RulesPerDst)
		}
		var list ruleList
		list.Count = uint32(len(slots))
		copy(list.Slots[:], slots)
		if err := trie.Put(lpmKey(prefix), list); err != nil {
			return fmt.Errorf("add %s to rule trie: %w", prefix, err)
		}
	}
	if err := outer.Put(uint32(0), trie); err != nil {
		return fmt.Errorf("install rule trie: %w", err)
	}
	return nil
}

func lpmKey(p netip.Prefix) any {
	if p.Addr().Is4() {
		return lpmKeyV4{Prefixlen: uint32(p.Bits()), Data: p.Addr().As4()}
	}
	return lpmKeyV6{Prefixlen: uint32(p.Bits()), Data: p.Addr().As16()}
}

// RuleMatches returns per-action match counts summed over CPUs.
func (m *Maps) RuleMatches() (map[uint8]uint64, error) {
	if m.RuleMatchCounts == nil {
		return nil, errors.New("rule_matches map not loaded")
	}
	out := make(map[uint8]uint64, len(RuleActionNames))
	for action := range RuleActionNames {
		var perCPU []uint64
		if err := m.RuleMatchCounts.Lookup(uint32(action), &perCPU); err != nil {
			return nil, fmt.Errorf("read rule_matches[%d]: %w", action, err)
		}
		for _, v := range perCPU {
			out[action] += v
		}
	}
	return out, nil
}
