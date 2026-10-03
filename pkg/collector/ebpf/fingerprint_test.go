package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestFingerprintLayout(t *testing.T) {
	if got := binary.Size(FingerprintKey{}); got != 32 {
		t.Errorf("fp_key size = %d, want 32", got)
	}
	if got := binary.Size(fpOverflow{}); got != 16 {
		t.Errorf("fp_overflow size = %d, want 16", got)
	}
	src, err := os.ReadFile("c/protector.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		fmt.Sprintf("#define FP_MAP_SIZE %d\n", FingerprintMapSize),
		fmt.Sprintf("#define CONFIG_KEY_FINGERPRINT %d\n", configKeyFingerprint),
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("protector.bpf.c lacks %q", strings.TrimSpace(want))
		}
	}
}

func TestFingerprintBuckets(t *testing.T) {
	for _, tc := range []struct {
		len  uint16
		want uint8
	}{{0, 0}, {127, 0}, {128, 1}, {255, 1}, {256, 2}, {496, 2}, {511, 2}, {512, 3}, {1023, 3}, {1024, 4}, {65535, 4}} {
		if got := FingerprintSizeBucket(tc.len); got != tc.want {
			t.Errorf("size bucket(%d) = %d, want %d", tc.len, got, tc.want)
		}
	}
	for _, tc := range []struct{ ttl, want uint8 }{{0, 0}, {31, 0}, {32, 1}, {64, 2}, {128, 4}, {255, 7}} {
		if got := FingerprintTTLBucket(tc.ttl); got != tc.want {
			t.Errorf("ttl bucket(%d) = %d, want %d", tc.ttl, got, tc.want)
		}
	}
	for src, want := range map[string]string{
		"198.51.100.77":         "198.51.100.0",
		"2001:db8:aa:bbbb::1":   "2001:db8:aa::",
		"2001:db8:aa:ffff:ff::": "2001:db8:aa::",
	} {
		if got := FingerprintSrcNet(net.ParseIP(src)); !got.Equal(net.ParseIP(want)) {
			t.Errorf("src net(%s) = %s, want %s", src, got, want)
		}
	}
}

func TestFingerprintKeyAddrs(t *testing.T) {
	v4 := FingerprintKey{Family: 0}
	copy(v4.Dst[:], net.ParseIP("192.0.2.9").To4())
	copy(v4.SrcNet[:], net.ParseIP("198.51.100.0").To4())
	if ip := v4.DstIP(); len(ip) != 4 || !ip.Equal(net.ParseIP("192.0.2.9")) {
		t.Errorf("v4 DstIP = %v", ip)
	}
	if ip := v4.SrcNetIP(); len(ip) != 4 || !ip.Equal(net.ParseIP("198.51.100.0")) {
		t.Errorf("v4 SrcNetIP = %v", ip)
	}

	v6 := FingerprintKey{Family: 1}
	copy(v6.Dst[:], net.ParseIP("2001:db8::9"))
	copy(v6.SrcNet[:], net.ParseIP("2001:db8:aa::")[:8])
	if ip := v6.DstIP(); len(ip) != 16 || !ip.Equal(net.ParseIP("2001:db8::9")) {
		t.Errorf("v6 DstIP = %v", ip)
	}
	if ip := v6.SrcNetIP(); len(ip) != 16 || !ip.Equal(net.ParseIP("2001:db8:aa::")) {
		t.Errorf("v6 SrcNetIP = %v", ip)
	}
}

func TestSumFingerprints(t *testing.T) {
	keys := []FingerprintKey{{Proto: 17}, {Proto: 6}, {Proto: 1}}
	// Three CPUs per key; the third key only has zeroes, as a key inserted
	// and then deleted mid-batch can.
	perCPU := []ScrubCounter{
		{1, 100}, {2, 200}, {0, 0},
		{0, 0}, {0, 0}, {5, 300},
		{0, 0}, {0, 0}, {0, 0},
	}
	got := sumFingerprints(keys, perCPU, 3)
	if len(got) != 2 {
		t.Fatalf("got %d fingerprints, want 2: %+v", len(got), got)
	}
	if got[0].Key.Proto != 17 || got[0].Packets != 3 || got[0].Bytes != 300 {
		t.Errorf("first = %+v, want proto 17, 3 packets, 300 bytes", got[0])
	}
	if got[1].Key.Proto != 6 || got[1].Packets != 5 || got[1].Bytes != 300 {
		t.Errorf("second = %+v, want proto 6, 5 packets, 300 bytes", got[1])
	}
}
