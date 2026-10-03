//go:build linux && e2e_ebpf

// Runs xdp_scrub through BPF_PROG_TEST_RUN (no interfaces needed) to check
// the fingerprint keys it records and its behaviour once the map is full.
//
//	sudo -E go test -tags e2e_ebpf -run TestScrubFingerprint -v ./pkg/collector/
package collector

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/collector/ebpf"
)

type fpPacket struct {
	src, dst net.IP
	proto    uint8
	ttl      uint8
	sport    uint16
	dport    uint16
	payload  int
}

// frame builds an Ethernet frame; checksums are irrelevant to xdp_scrub.
func (p fpPacket) frame() []byte {
	l4 := make([]byte, 8+p.payload)
	binary.BigEndian.PutUint16(l4[0:], p.sport)
	binary.BigEndian.PutUint16(l4[2:], p.dport)
	binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
	switch p.proto {
	case 1, 58:
		l4[0], l4[1] = 8, 0 // echo request, not a port
	case 6:
		l4[12], l4[13] = 0x50, 0x10 // 20-byte header, ACK: not a bad-flags scan
	}
	eth := make([]byte, 14)
	if v4 := p.src.To4(); v4 != nil {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		ip[8], ip[9] = p.ttl, p.proto
		copy(ip[12:], v4)
		copy(ip[16:], p.dst.To4())
		return append(append(eth, ip...), l4...)
	}
	binary.BigEndian.PutUint16(eth[12:], 0x86DD)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
	ip[6], ip[7] = p.proto, p.ttl
	copy(ip[8:], p.src.To16())
	copy(ip[24:], p.dst.To16())
	return append(append(eth, ip...), l4...)
}

func (p fpPacket) ipLen() uint16 {
	if p.src.To4() != nil {
		return uint16(20 + 8 + p.payload)
	}
	return uint16(40 + 8 + p.payload)
}

func loadScrubForTest(t *testing.T, fingerprints bool) (*ebpf.Loader, *cebpf.Program) {
	t.Helper()
	requireRoot(t)
	l := ebpf.NewLoader(ebpf.LoaderConfig{Mode: ebpf.ModeScrub, Fingerprints: fingerprints})
	if err := l.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(l.Close)
	prog := l.Program("xdp_scrub")
	if prog == nil {
		t.Fatal("xdp_scrub not loaded")
	}
	return l, prog
}

func runPacket(t *testing.T, prog *cebpf.Program, frame []byte) {
	t.Helper()
	if _, err := prog.Run(&cebpf.RunOptions{Data: frame}); err != nil {
		t.Fatalf("prog run: %v", err)
	}
}

func TestScrubFingerprintKeys(t *testing.T) {
	l, prog := loadScrubForTest(t, true)
	maps := l.GetMaps()
	f := newFingerprinter(maps)
	if err := f.start(); err != nil {
		t.Fatal(err)
	}
	blocked := net.ParseIP("203.0.113.66")
	if err := maps.BlockIP(blocked, "test", logrus.Fields{}); err != nil {
		t.Fatal(err)
	}

	dst4, dst6 := net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8:1::10")
	cases := []struct {
		pkt     fpPacket
		dropped bool
	}{
		{fpPacket{net.ParseIP("198.51.100.7"), dst4, 17, 64, 123, 5410, 468}, false},      // 496: bucket 2
		{fpPacket{net.ParseIP("198.51.100.8"), dst4, 17, 31, 1, 1, 99}, false},            // 127, ttl 0
		{fpPacket{net.ParseIP("198.51.101.8"), dst4, 17, 32, 1, 2, 100}, false},           // 128, ttl 1
		{fpPacket{net.ParseIP("198.51.102.8"), dst4, 6, 255, 1, 3, 995}, false},           // 1023, ttl 7
		{fpPacket{net.ParseIP("198.51.103.8"), dst4, 17, 128, 1, 4, 996}, false},          // 1024
		{fpPacket{net.ParseIP("198.51.104.8"), dst4, 1, 64, 0, 0, 56}, false},             // ICMP: port 0
		{fpPacket{blocked, dst4, 17, 64, 123, 5410, 468}, true},                           // blocked_ips
		{fpPacket{net.ParseIP("2001:db8:aa:bb::7"), dst6, 17, 64, 123, 5410, 468}, false}, // 516: bucket 3
		{fpPacket{net.ParseIP("2001:db8:aa:cc::7"), dst6, 17, 64, 123, 5410, 79}, false},  // 127
	}
	for _, c := range cases {
		runPacket(t, prog, c.pkt.frame())
	}

	fps, _, err := f.flip()
	if err != nil {
		t.Fatal(err)
	}
	got := map[ebpf.FingerprintKey]ebpf.Fingerprint{}
	for _, fp := range fps {
		got[fp.Key] = fp
	}
	for i, c := range cases {
		var k ebpf.FingerprintKey
		p := c.pkt
		if v4 := p.dst.To4(); v4 != nil {
			copy(k.Dst[:], v4)
			copy(k.SrcNet[:], ebpf.FingerprintSrcNet(p.src).To4())
		} else {
			copy(k.Dst[:], p.dst.To16())
			copy(k.SrcNet[:], ebpf.FingerprintSrcNet(p.src))
			k.Family = 1
		}
		k.Proto = p.proto
		if p.proto == 6 || p.proto == 17 {
			k.DstPort = p.dport
		}
		k.SizeBucket = ebpf.FingerprintSizeBucket(p.ipLen())
		k.TTLBucket = ebpf.FingerprintTTLBucket(p.ttl)
		if c.dropped {
			k.Dropped = 1
		}
		fp, ok := got[k]
		if !ok {
			t.Errorf("case %d: no bucket %+v; have %+v", i, k, fps)
			continue
		}
		if fp.Packets != 1 || fp.Bytes != uint64(p.ipLen()) {
			t.Errorf("case %d: %d packets, %d bytes; want 1, %d", i, fp.Packets, fp.Bytes, p.ipLen())
		}
	}
	if len(fps) != len(cases) {
		t.Errorf("got %d buckets, want %d", len(fps), len(cases))
	}

	// Nothing recorded since the flip is left in the drained map.
	if fps, _, err := f.flip(); err != nil || len(fps) != 0 {
		t.Errorf("second flip: %d buckets, err %v; want none", len(fps), err)
	}

	// Generation 0 stops counting.
	if err := maps.SetFingerprintGeneration(0); err != nil {
		t.Fatal(err)
	}
	runPacket(t, prog, cases[0].pkt.frame())
	for _, gen := range []uint32{1, 2} {
		if fps, err := maps.DrainFingerprints(gen); err != nil || len(fps) != 0 {
			t.Errorf("off: generation %d map has %d buckets, err %v", gen, len(fps), err)
		}
	}
}

// Random /24s fill the map; the overflow counter must account for every
// packet that did not fit, and the next generation must start fresh.
func TestScrubFingerprintMapFull(t *testing.T) {
	l, prog := loadScrubForTest(t, true)
	maps := l.GetMaps()
	f := newFingerprinter(maps)
	if err := f.start(); err != nil {
		t.Fatal(err)
	}
	pkt := fpPacket{dst: net.ParseIP("192.0.2.10"), proto: 17, ttl: 64, sport: 1, dport: 53, payload: 32}
	const extra = 5000
	total := ebpf.FingerprintMapSize + extra
	// Distinct /24s: 10.0.0.0/8 has 65536 of them, so use two /8s.
	for i := range total {
		pkt.src = net.IPv4(byte(10+i>>16), byte(i>>8), byte(i), byte(rand.IntN(256)))
		runPacket(t, prog, pkt.frame())
	}
	over, err := maps.FingerprintOverflow()
	if err != nil {
		t.Fatal(err)
	}
	fps, _, err := f.flip()
	if err != nil {
		t.Fatal(err)
	}
	var counted uint64
	for _, fp := range fps {
		counted += fp.Packets
	}
	t.Logf("%d buckets, %d packets counted, %d overflowed", len(fps), counted, over)
	if over < extra || counted+over != uint64(total) {
		t.Errorf("counted %d + overflow %d, want %d with overflow >= %d", counted, over, total, extra)
	}
	if len(fps) > ebpf.FingerprintMapSize {
		t.Errorf("%d buckets exceed the map size", len(fps))
	}

	// The drained map takes new buckets again once it is active.
	if _, _, err := f.flip(); err != nil {
		t.Fatal(err)
	}
	pkt.src = net.ParseIP("198.51.100.1")
	runPacket(t, prog, pkt.frame())
	fps, _, err = f.flip()
	if err != nil || len(fps) != 1 {
		t.Errorf("after drain: %d buckets, err %v; want 1", len(fps), err)
	}
	if after, _ := maps.FingerprintOverflow(); after != over {
		t.Errorf("overflow rose from %d to %d with a drained map", over, after)
	}
}

// Disabled fingerprints shrink the maps, and XDP never touches them.
func TestScrubFingerprintsOffShrinksMaps(t *testing.T) {
	l, _ := loadScrubForTest(t, false)
	info, err := l.GetMaps().FingerprintsA.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxEntries != 1 {
		t.Errorf("fingerprints_a max_entries = %d, want 1", info.MaxEntries)
	}
}
