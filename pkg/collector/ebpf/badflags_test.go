package ebpf

import (
	"testing"
	"unsafe"
)

func TestBadFlagsScanName(t *testing.T) {
	tests := []struct {
		scanType uint32
		want     string
	}{
		{BadFlagsScanNone, "unknown"},
		{BadFlagsScanSynFin, "syn_fin"},
		{BadFlagsScanXmas, "xmas"},
		{BadFlagsScanNull, "null_scan"},
		{99, "unknown"},
	}
	for _, tt := range tests {
		if got := BadFlagsScanName(tt.scanType); got != tt.want {
			t.Errorf("BadFlagsScanName(%d) = %q, want %q", tt.scanType, got, tt.want)
		}
	}
}

func TestBadFlagsInfoLayout(t *testing.T) {
	// Mirrors struct bad_flags_info in protector.bpf.c: __u64 last_seen;
	// __u32 scan_type; __u32 flags_raw. Verify no unexpected padding sneaks
	// in that would break the cilium/ebpf map value marshaling.
	var info BadFlagsInfo
	const wantSize = 16 // 8 + 4 + 4
	if got := unsafe.Sizeof(info); got != wantSize {
		t.Errorf("unsafe.Sizeof(BadFlagsInfo{}) = %d, want %d", got, wantSize)
	}
}
