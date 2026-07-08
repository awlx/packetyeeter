package ebpf

import (
	"net"
	"testing"
)

func TestParsePolicyAction(t *testing.T) {
	tests := []struct {
		in      string
		want    PolicyAction
		wantErr bool
	}{
		{"block", PolicyBlock, false},
		{"Block", PolicyBlock, false},
		{"monitor", PolicyMonitor, false},
		{"MONITOR", PolicyMonitor, false},
		{"drop", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParsePolicyAction(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePolicyAction(%q) expected error, got nil", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePolicyAction(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParsePolicyAction(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestPolicyActionString(t *testing.T) {
	if PolicyBlock.String() != "block" {
		t.Errorf("PolicyBlock.String() = %q, want block", PolicyBlock.String())
	}
	if PolicyMonitor.String() != "monitor" {
		t.Errorf("PolicyMonitor.String() = %q, want monitor", PolicyMonitor.String())
	}
	if PolicyAction(99).String() != "unknown" {
		t.Errorf("PolicyAction(99).String() = %q, want unknown", PolicyAction(99).String())
	}
}

// TestSetPoliciesNilMaps ensures SetPolicies tolerates unset map handles
// (e.g. a Maps value built by a test harness without a loaded kernel
// program) instead of panicking.
func TestSetPoliciesNilMaps(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	m := &Maps{}
	if err := m.SetPolicies([]PolicyRule{{Net: ipNet, Action: PolicyBlock}}); err != nil {
		t.Errorf("SetPolicies with nil map handles returned error: %v", err)
	}
}

func TestSetPoliciesInvalidNet(t *testing.T) {
	m := &Maps{}
	if err := m.SetPolicies([]PolicyRule{{Net: nil, Action: PolicyBlock}}); err == nil {
		t.Error("SetPolicies with nil Net expected an error, got nil")
	}
}
