package ebpf

import (
	"encoding/binary"
	"testing"
)

// Sizes must match the C structs in protector.bpf.c byte for byte.
func TestRuleLayout(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want int
	}{
		{"scrub_rule", ScrubRule{}, 392},
		{"rule_list", ruleList{}, 68},
		{"rule_bucket", ruleBucket{}, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := binary.Size(tt.v); got != tt.want {
				t.Fatalf("binary.Size = %d, want %d", got, tt.want)
			}
		})
	}
}
