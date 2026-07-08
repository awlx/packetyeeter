package ebpf

import (
	"testing"
	"unsafe"
)

func TestIncidentReasonName(t *testing.T) {
	tests := []struct {
		reason uint8
		want   string
	}{
		{IncidentBlockedIP, "blocked_ip"},
		{IncidentPolicyBlock, "policy_block"},
		{IncidentICMPRate, "icmp_rate"},
		{IncidentUDPRate, "udp_rate"},
		{IncidentUDPFrag, "udp_frag"},
		{IncidentBadFlags, "bad_flags"},
		{0, "unknown"},
		{99, "unknown"},
	}
	for _, tt := range tests {
		if got := IncidentReasonName(tt.reason); got != tt.want {
			t.Errorf("IncidentReasonName(%d) = %q, want %q", tt.reason, got, tt.want)
		}
	}
}

func TestIncidentEventLayout(t *testing.T) {
	// Mirrors struct incident_event in protector.bpf.c: __u64 timestamp;
	// __u32 saddr_v4; __u8 saddr_v6[16]; __u8 is_v6; __u8 reason;
	// __u8 pad[2]. Verify the Go struct is exactly 32 bytes with no
	// unexpected padding, so binary.Read can decode the raw perf sample
	// directly.
	var inc IncidentEvent
	const wantSize = 32 // 8 + 4 + 16 + 1 + 1 + 2
	if got := unsafe.Sizeof(inc); got != wantSize {
		t.Errorf("unsafe.Sizeof(IncidentEvent{}) = %d, want %d", got, wantSize)
	}
}
