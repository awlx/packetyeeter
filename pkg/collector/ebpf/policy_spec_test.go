//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"io/fs"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

// Parses the compiled object only (no load), so it needs `make bpf` but not
// root. It keeps PolicyFamilyNames and PolicyCounter in step with
// POLICY_STATS_SIZE and struct policy_counter in protector.bpf.c.
func TestPolicyBlockStatsMatchesSpec(t *testing.T) {
	obj, err := bpfFS.ReadFile("c/protector.bpf.o")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("c/protector.bpf.o not built; run `make bpf`")
	}
	if err != nil {
		t.Fatalf("read embedded BPF object: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		t.Fatalf("load BPF spec: %v", err)
	}
	m, ok := spec.Maps["policy_block_stats"]
	if !ok {
		t.Fatal("policy_block_stats map missing from BPF spec")
	}
	if m.Type != ebpf.PerCPUArray {
		t.Errorf("policy_block_stats type = %v, want %v", m.Type, ebpf.PerCPUArray)
	}
	if got, want := len(PolicyFamilyNames), int(m.MaxEntries); got != want {
		t.Errorf("len(PolicyFamilyNames) = %d, want POLICY_STATS_SIZE = %d", got, want)
	}
	if got, want := unsafe.Sizeof(PolicyCounter{}), uintptr(m.ValueSize); got != want {
		t.Errorf("sizeof(PolicyCounter) = %d, want struct policy_counter size %d", got, want)
	}
}
