package ebpf

import (
	"fmt"
	"net"
)

// PolicyAction mirrors the POLICY_* constants in protector.bpf.c.
type PolicyAction uint32

const (
	// PolicyBlock always drops matching traffic outright (subject to the
	// same global dry-run/monitor override as every other kernel-space
	// detection, so a new policy can be dry-run before it takes effect).
	PolicyBlock PolicyAction = 1
	// PolicyMonitor forces monitor-mode (log-only, never drop) for
	// matching sources, even when the collector is otherwise enforcing.
	// Useful for known-good-but-not-quite-allowlisted ranges, or for
	// staging a new block policy's blast radius before enabling it.
	PolicyMonitor PolicyAction = 2
)

func (a PolicyAction) String() string {
	switch a {
	case PolicyBlock:
		return "block"
	case PolicyMonitor:
		return "monitor"
	default:
		return "unknown"
	}
}

// ParsePolicyAction parses the string form used in -policy flag values and
// policy config files ("block" or "monitor", case-insensitive).
func ParsePolicyAction(s string) (PolicyAction, error) {
	switch s {
	case "block", "BLOCK", "Block":
		return PolicyBlock, nil
	case "monitor", "MONITOR", "Monitor":
		return PolicyMonitor, nil
	default:
		return 0, fmt.Errorf("unknown policy action %q (want \"block\" or \"monitor\")", s)
	}
}

// PolicyRule is a single per-CIDR policy engine entry.
type PolicyRule struct {
	Net    *net.IPNet
	Action PolicyAction
}

// policyEntry mirrors `struct policy_entry` in protector.bpf.c.
type policyEntry struct {
	Action uint32
}

// SetPolicies replaces the kernel-space policy engine maps with rules. It is
// intended for one-time startup population from the configured -policy
// flag; it does not attempt incremental add/remove semantics (unlike the
// allowlist's AddAllowlistEntry/RemoveAllowlistEntry), since policy rules
// are expected to be operator-configured at startup rather than mutated at
// runtime by the analyzer.
func (m *Maps) SetPolicies(rules []PolicyRule) error {
	var firstErr error
	for _, rule := range rules {
		if err := m.addPolicyRule(rule); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *Maps) addPolicyRule(rule PolicyRule) error {
	v4, v6, err := lpmKeyFromNet(rule.Net)
	if err != nil {
		return err
	}

	value := policyEntry{Action: uint32(rule.Action)}

	if v4 != nil {
		if m.PolicyV4 == nil {
			return nil
		}
		if err := m.PolicyV4.Put(v4, value); err != nil {
			return fmt.Errorf("failed to add policy rule %s (%s) to kernel IPv4 policy map: %w", rule.Net, rule.Action, err)
		}
		return nil
	}

	if m.PolicyV6 == nil {
		return nil
	}
	if err := m.PolicyV6.Put(v6, value); err != nil {
		return fmt.Errorf("failed to add policy rule %s (%s) to kernel IPv6 policy map: %w", rule.Net, rule.Action, err)
	}
	return nil
}
