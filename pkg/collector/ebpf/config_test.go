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

func TestParseUDPFragMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint32
		ok   bool
	}{
		{in: "", want: UDPFragModeRate, ok: true},
		{in: "rate", want: UDPFragModeRate, ok: true},
		{in: "drop", want: UDPFragModeDrop, ok: true},
		{in: "block", ok: false},
	} {
		got, err := ParseUDPFragMode(tc.in)
		if tc.ok {
			if err != nil {
				t.Fatalf("ParseUDPFragMode(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseUDPFragMode(%q)=%d, want %d", tc.in, got, tc.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("ParseUDPFragMode(%q) expected error", tc.in)
		}
	}
}

func TestSetUDPFragModeNilConfigMapNoop(t *testing.T) {
	m := &Maps{}
	if err := m.SetUDPFragMode(UDPFragModeRate); err != nil {
		t.Fatalf("SetUDPFragMode with nil ConfigMap: %v", err)
	}
	if err := m.SetUDPFragMode(99); err == nil {
		t.Fatal("expected invalid mode error even with nil map")
	}
}
