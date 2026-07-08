package collector

import (
	"testing"

	"PacketYeeter/pkg/collector/ebpf"
)

func TestParsePolicyRules(t *testing.T) {
	rules, err := parsePolicyRules("203.0.113.0/24=block,198.51.100.0/24=monitor,2001:db8::/32=block")
	if err != nil {
		t.Fatalf("parsePolicyRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	if rules[0].Net.String() != "203.0.113.0/24" || rules[0].Action != ebpf.PolicyBlock {
		t.Errorf("rule[0] = %+v, want 203.0.113.0/24 block", rules[0])
	}
	if rules[1].Net.String() != "198.51.100.0/24" || rules[1].Action != ebpf.PolicyMonitor {
		t.Errorf("rule[1] = %+v, want 198.51.100.0/24 monitor", rules[1])
	}
	if rules[2].Net.String() != "2001:db8::/32" || rules[2].Action != ebpf.PolicyBlock {
		t.Errorf("rule[2] = %+v, want 2001:db8::/32 block", rules[2])
	}
}

func TestParsePolicyRulesSingleIPNoMask(t *testing.T) {
	rules, err := parsePolicyRules("203.0.113.42=block")
	if err != nil {
		t.Fatalf("parsePolicyRules: %v", err)
	}
	if len(rules) != 1 || rules[0].Net.String() != "203.0.113.42/32" {
		t.Fatalf("expected single /32 rule, got %+v", rules)
	}
}

func TestParsePolicyRulesEmpty(t *testing.T) {
	rules, err := parsePolicyRules("")
	if err != nil {
		t.Fatalf("parsePolicyRules(\"\") unexpected error: %v", err)
	}
	if rules != nil {
		t.Fatalf("expected nil rules for empty spec, got %+v", rules)
	}
}

func TestParsePolicyRulesInvalidEntriesReported(t *testing.T) {
	// A malformed entry should be reported but not prevent parsing the
	// rest of the valid entries.
	rules, err := parsePolicyRules("not-a-cidr=block,203.0.113.0/24=block,203.0.113.1=bogus-action")
	if err == nil {
		t.Fatal("expected an error for malformed policy entries, got nil")
	}
	if len(rules) != 1 || rules[0].Net.String() != "203.0.113.0/24" {
		t.Fatalf("expected the one valid rule to still parse, got %+v", rules)
	}
}
