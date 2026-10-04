package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
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

// fakeFPMap is a per-CPU fingerprint map on a kernel without batch ops.
type fakeFPMap struct {
	entries map[FingerprintKey][]ScrubCounter
	order   []FingerprintKey
	deleted []FingerprintKey
	failAt  int // iteration fails before this position when > 0
}

func (m *fakeFPMap) String() string { return "fake-fp" }

func (m *fakeFPMap) BatchLookupAndDelete(*ebpf.MapBatchCursor, any, any, *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("map batch lookup and delete: %w", ebpf.ErrNotSupported)
}

func (m *fakeFPMap) Delete(key any) error {
	k := *key.(*FingerprintKey)
	if _, ok := m.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, k)
	m.deleted = append(m.deleted, k)
	return nil
}

type fakeFPIter struct {
	m   *fakeFPMap
	pos int
	err error
}

func (it *fakeFPIter) Next(k, v any) bool {
	for it.pos < len(it.m.order) {
		if it.m.failAt > 0 && it.pos == it.m.failAt {
			it.err = errors.New("iteration aborted")
			return false
		}
		key := it.m.order[it.pos]
		it.pos++
		if val, ok := it.m.entries[key]; ok {
			*k.(*FingerprintKey) = key
			*v.(*[]ScrubCounter) = append([]ScrubCounter(nil), val...)
			return true
		}
	}
	return false
}

func (it *fakeFPIter) Err() error { return it.err }

func (m *fakeFPMap) iterate() entryIterator { return &fakeFPIter{m: m} }

func TestDrainFingerprintsWithoutBatchOps(t *testing.T) {
	m := &fakeFPMap{entries: map[FingerprintKey][]ScrubCounter{}}
	for i, pc := range [][]ScrubCounter{
		{{1, 100}, {2, 200}},
		{{0, 0}, {4, 400}},
		{{0, 0}, {0, 0}},
	} {
		k := FingerprintKey{Proto: uint8(i + 1)}
		m.entries[k] = pc
		m.order = append(m.order, k)
	}

	got, err := drainFingerprints(m, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Packets != 3 || got[0].Bytes != 300 || got[1].Packets != 4 {
		t.Fatalf("drained %+v, want 3 and 4 packets", got)
	}
	if len(m.entries) != 0 || len(m.deleted) != 3 {
		t.Fatalf("%d entries left, %d deleted; want the map emptied", len(m.entries), len(m.deleted))
	}
}

func TestDrainFingerprintsIterErrorDeletesWhatWasRead(t *testing.T) {
	m := &fakeFPMap{entries: map[FingerprintKey][]ScrubCounter{}, failAt: 2}
	for i := range 3 {
		k := FingerprintKey{Proto: uint8(i + 1)}
		m.entries[k] = []ScrubCounter{{1, 10}}
		m.order = append(m.order, k)
	}

	got, err := drainFingerprints(m, 1)
	if err == nil {
		t.Fatal("iteration error not returned")
	}
	if len(got) != 2 || len(m.deleted) != 2 || len(m.entries) != 1 {
		t.Fatalf("got %d fps, deleted %d, %d left; want 2 read and deleted, 1 left", len(got), len(m.deleted), len(m.entries))
	}

	m.failAt = 0
	got, err = drainFingerprints(m, 1)
	if err != nil || len(got) != 1 || len(m.entries) != 0 {
		t.Fatalf("retry: %d fps, err %v, %d left; want the rest drained", len(got), err, len(m.entries))
	}
}
