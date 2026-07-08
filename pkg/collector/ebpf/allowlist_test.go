package ebpf

import (
	"net"
	"testing"
)

func TestLpmKeyFromNetIPv4(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	v4, v6, err := lpmKeyFromNet(ipNet)
	if err != nil {
		t.Fatalf("lpmKeyFromNet: %v", err)
	}
	if v6 != nil {
		t.Fatalf("expected nil v6 key for IPv4 network, got %+v", v6)
	}
	if v4 == nil {
		t.Fatal("expected non-nil v4 key")
	}
	if v4.Prefixlen != 24 {
		t.Errorf("Prefixlen = %d, want 24", v4.Prefixlen)
	}
	want := [4]byte{203, 0, 113, 0}
	if v4.Data != want {
		t.Errorf("Data = %v, want %v", v4.Data, want)
	}
}

func TestLpmKeyFromNetIPv4Host(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("198.51.100.7/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	v4, _, err := lpmKeyFromNet(ipNet)
	if err != nil {
		t.Fatalf("lpmKeyFromNet: %v", err)
	}
	if v4.Prefixlen != 32 {
		t.Errorf("Prefixlen = %d, want 32", v4.Prefixlen)
	}
	want := [4]byte{198, 51, 100, 7}
	if v4.Data != want {
		t.Errorf("Data = %v, want %v", v4.Data, want)
	}
}

func TestLpmKeyFromNetIPv6(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("2001:db8::/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	v4, v6, err := lpmKeyFromNet(ipNet)
	if err != nil {
		t.Fatalf("lpmKeyFromNet: %v", err)
	}
	if v4 != nil {
		t.Fatalf("expected nil v4 key for IPv6 network, got %+v", v4)
	}
	if v6 == nil {
		t.Fatal("expected non-nil v6 key")
	}
	if v6.Prefixlen != 32 {
		t.Errorf("Prefixlen = %d, want 32", v6.Prefixlen)
	}
	want := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	if v6.Data != want {
		t.Errorf("Data = %v, want %v", v6.Data, want)
	}
}

func TestLpmKeyFromNetNil(t *testing.T) {
	if _, _, err := lpmKeyFromNet(nil); err == nil {
		t.Fatal("expected error for nil network")
	}
}

// TestAllowlistNilMapsNoop ensures that calling the allowlist helpers on a
// Maps value with no underlying eBPF maps (e.g. before Start() has loaded
// the collector, or on unsupported platforms) is a safe no-op rather than
// a nil-pointer panic.
func TestAllowlistNilMapsNoop(t *testing.T) {
	m := &Maps{}
	_, ipNet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	if err := m.AddAllowlistEntry(ipNet); err != nil {
		t.Errorf("AddAllowlistEntry with nil maps returned error: %v", err)
	}
	if err := m.RemoveAllowlistEntry(ipNet); err != nil {
		t.Errorf("RemoveAllowlistEntry with nil maps returned error: %v", err)
	}
	if err := m.SyncAllowlist([]*net.IPNet{ipNet}); err != nil {
		t.Errorf("SyncAllowlist with nil maps returned error: %v", err)
	}
}
