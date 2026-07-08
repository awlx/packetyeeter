package ebpf

import "testing"

func TestSetMonitorModeNilConfigMapNoop(t *testing.T) {
	m := &Maps{}

	if err := m.SetMonitorMode(true); err != nil {
		t.Fatalf("SetMonitorMode(true) with nil ConfigMap returned error: %v", err)
	}
	if !m.DryRun {
		t.Error("DryRun = false, want true after SetMonitorMode(true)")
	}

	if err := m.SetMonitorMode(false); err != nil {
		t.Fatalf("SetMonitorMode(false) with nil ConfigMap returned error: %v", err)
	}
	if m.DryRun {
		t.Error("DryRun = true, want false after SetMonitorMode(false)")
	}
}
