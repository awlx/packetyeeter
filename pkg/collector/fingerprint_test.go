package collector

import (
	"errors"
	"net"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"

	"github.com/sirupsen/logrus"
)

// fakeFPStore models the two maps and the XDP side's generation choice.
type fakeFPStore struct {
	gen     uint32
	maps    [2][]ebpf.Fingerprint
	drained []uint32
	setErr  error
	events  []string
	// drainFail makes the next drain return only the first entry and an
	// error, keeping the rest in the map.
	drainFail bool
}

func (s *fakeFPStore) SetFingerprintGeneration(gen uint32) error {
	if s.setErr != nil {
		return s.setErr
	}
	s.gen = gen
	s.events = append(s.events, "set")
	return nil
}

func (s *fakeFPStore) DrainFingerprints(gen uint32) ([]ebpf.Fingerprint, error) {
	if gen&1 == s.gen&1 {
		return nil, errors.New("drained the map XDP is writing to")
	}
	s.events = append(s.events, "drain")
	s.drained = append(s.drained, gen)
	if s.drainFail && len(s.maps[gen&1]) > 1 {
		s.drainFail = false
		out := s.maps[gen&1][:1]
		s.maps[gen&1] = s.maps[gen&1][1:]
		return out, errors.New("iteration aborted")
	}
	out := s.maps[gen&1]
	s.maps[gen&1] = nil
	return out, nil
}

// packet records like XDP: into the map the current generation selects.
func (s *fakeFPStore) packet(fp ebpf.Fingerprint) {
	s.maps[s.gen&1] = append(s.maps[s.gen&1], fp)
}

func TestFingerprinterFlip(t *testing.T) {
	store := &fakeFPStore{}
	f := newFingerprinter(store)
	clock := time.Unix(1000, 0)
	f.now = func() time.Time { return clock }
	var slept time.Duration
	f.sleep = func(d time.Duration) {
		slept += d
		store.events = append(store.events, "sleep")
	}

	if err := f.start(); err != nil || store.gen != 1 {
		t.Fatalf("start: gen %d, err %v", store.gen, err)
	}
	store.packet(ebpf.Fingerprint{Packets: 1})
	clock = clock.Add(10 * time.Second)
	fps, elapsed, err := f.flip()
	if err != nil || len(fps) != 1 || elapsed != 10*time.Second {
		t.Fatalf("flip 1: %d fps, elapsed %s, err %v", len(fps), elapsed, err)
	}
	if store.gen != 2 || slept != fingerprintSettle {
		t.Errorf("after flip 1: gen %d, slept %s", store.gen, slept)
	}
	if got := store.events; len(got) != 4 || got[1] != "set" || got[2] != "sleep" || got[3] != "drain" {
		t.Errorf("events = %v, want set, set, sleep, drain", got)
	}

	// Packets after the flip land in the other map and are not lost.
	store.packet(ebpf.Fingerprint{Packets: 2})
	store.packet(ebpf.Fingerprint{Packets: 3})
	fps, _, err = f.flip()
	if err != nil || len(fps) != 2 {
		t.Fatalf("flip 2: %d fps, err %v", len(fps), err)
	}
	if store.drained[0] != 1 || store.drained[1] != 2 {
		t.Errorf("drained generations %v, want [1 2]", store.drained)
	}

	store.setErr = errors.New("boom")
	if _, _, err := f.flip(); err == nil || f.gen != 3 {
		t.Errorf("failed switch: err %v, gen %d; want an error and the generation kept", err, f.gen)
	}
}

func TestFingerprinterRetriesPartialDrain(t *testing.T) {
	store := &fakeFPStore{}
	f := newFingerprinter(store)
	f.sleep = func(time.Duration) {}
	if err := f.start(); err != nil {
		t.Fatal(err)
	}
	store.packet(ebpf.Fingerprint{Packets: 1})
	store.packet(ebpf.Fingerprint{Packets: 2})
	store.drainFail = true
	fps, _, err := f.flip()
	if err == nil || len(fps) != 1 || f.retry != 1 {
		t.Fatalf("flip 1: %d fps, err %v, retry %d; want 1 fp, an error and gen 1 to retry", len(fps), err, f.retry)
	}

	// The leftover of map 1 is drained before XDP switches back to it.
	store.packet(ebpf.Fingerprint{Packets: 3})
	fps, _, err = f.flip()
	if err != nil || len(fps) != 2 || f.retry != 0 {
		t.Fatalf("flip 2: %d fps, err %v, retry %d; want the leftover and the new fp", len(fps), err, f.retry)
	}
	if fps[0].Packets != 2 || fps[1].Packets != 3 {
		t.Errorf("flip 2 fps = %+v, want 2 then 3 packets", fps)
	}
	if len(store.maps[1]) != 0 {
		t.Errorf("map 1 still holds %d entries after XDP switched back", len(store.maps[1]))
	}
}

func TestNextGenerationAlternatesAcrossWrap(t *testing.T) {
	for _, gen := range []uint32{1, 2, 0xFFFFFFFE, 0xFFFFFFFF} {
		next := nextGeneration(gen)
		if next == 0 || next&1 == gen&1 {
			t.Errorf("nextGeneration(%#x) = %#x: must be non-zero with the other parity", gen, next)
		}
	}
}

func fpFor(dst string, port uint16, packets uint64) ebpf.Fingerprint {
	var k ebpf.FingerprintKey
	ip := net.ParseIP(dst)
	if v4 := ip.To4(); v4 != nil {
		copy(k.Dst[:], v4)
	} else {
		copy(k.Dst[:], ip)
		k.Family = 1
	}
	k.DstPort = port
	return ebpf.Fingerprint{Key: k, Packets: packets, Bytes: packets * 100}
}

func TestSelectTopFingerprints(t *testing.T) {
	var fps []ebpf.Fingerprint
	// a: 5 buckets, 15 packets; b: 2 buckets, 100 packets; c: 1 bucket, 1 packet.
	for i := range 5 {
		fps = append(fps, fpFor("192.0.2.1", uint16(i), uint64(i+1)))
	}
	fps = append(fps, fpFor("2001:db8::1", 1, 60), fpFor("2001:db8::1", 2, 40), fpFor("192.0.2.3", 1, 1))

	kept, cut := selectTopFingerprints(fps, 3, 2)
	if cut.destinations != 1 || cut.buckets != 1+2 {
		t.Errorf("cut = %+v, want 1 destination and 3 buckets", cut)
	}
	if len(kept) != 5 {
		t.Fatalf("kept %d buckets, want 5: %+v", len(kept), kept)
	}
	// Busiest destination first, buckets by packets within it.
	want := []uint64{60, 40, 5, 4, 3}
	for i, fp := range kept {
		if fp.Packets != want[i] {
			t.Errorf("kept[%d] = %d packets, want %d", i, fp.Packets, want[i])
		}
	}
	if !kept[0].Key.DstIP().Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("first destination = %s", kept[0].Key.DstIP())
	}

	kept, cut = selectTopFingerprints(fps, 32, 256)
	if len(kept) != len(fps) || cut != (fingerprintCut{}) {
		t.Errorf("under the caps: kept %d of %d, cut %+v", len(kept), len(fps), cut)
	}
	if kept, cut := selectTopFingerprints(nil, 32, 256); len(kept) != 0 || cut != (fingerprintCut{}) {
		t.Errorf("empty input: kept %d, cut %+v", len(kept), cut)
	}
}

// An IPv4 and an IPv6 destination with the same leading bytes stay apart.
func TestSelectTopFingerprintsFamilies(t *testing.T) {
	a := fpFor("192.0.2.1", 1, 1)
	b := a
	b.Key.Family = 1
	kept, cut := selectTopFingerprints([]ebpf.Fingerprint{a, b}, 1, 256)
	if len(kept) != 2 || cut.buckets != 0 {
		t.Errorf("kept %d, cut %+v; want both families kept", len(kept), cut)
	}
}

func TestFingerprintSignal(t *testing.T) {
	fp := fpFor("192.0.2.1", 5410, 7)
	fp.Key.Proto = 17
	fp.Key.SizeBucket = 2
	fp.Key.TTLBucket = 2
	fp.Key.Dropped = 1
	copy(fp.Key.SrcNet[:], net.ParseIP("198.51.100.0").To4())
	now := time.Unix(1700000000, 0)
	sig := fingerprintSignal("scrub-1", fp, 9600*time.Millisecond, now, 3)

	if sig.Type != apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT || sig.Source != apiv1.SignalSource_SOURCE_EBPF {
		t.Errorf("type/source = %s/%s", sig.Type, sig.Source)
	}
	if len(sig.Ip) != 0 {
		t.Errorf("Ip = %v, want empty so older analyzers drop it", sig.Ip)
	}
	f := sig.Fingerprint
	if f.CollectorId != "scrub-1" || f.Protocol != 17 || f.DstPort != 5410 || f.SizeBucket != 2 || f.TtlBucket != 2 ||
		!f.Dropped || f.Packets != 7 || f.Bytes != 700 || f.IntervalSeconds != 10 {
		t.Errorf("fingerprint = %+v", f)
	}
	if !net.IP(f.DstIp).Equal(net.ParseIP("192.0.2.1")) || len(f.DstIp) != 4 {
		t.Errorf("dst_ip = %v", f.DstIp)
	}
	if !net.IP(f.SrcNet).Equal(net.ParseIP("198.51.100.0")) || len(f.SrcNet) != 4 {
		t.Errorf("src_net = %v", f.SrcNet)
	}
	if s := fingerprintSignal("x", fp, 100*time.Millisecond, now, 0); s.Fingerprint.IntervalSeconds != 1 {
		t.Errorf("sub-second interval reported as %d s, want 1", s.Fingerprint.IntervalSeconds)
	}
}

// offerSignal must never block or evict what is already queued.
func TestOfferSignalDoesNotEvict(t *testing.T) {
	c := &Collector{signalQueue: make(chan *apiv1.Signal, 1), Logger: logrus.New()}
	first := &apiv1.Signal{Id: "detection"}
	c.signalQueue <- first
	c.offerSignal(&apiv1.Signal{Id: "fingerprint"})
	if got := <-c.signalQueue; got != first {
		t.Errorf("queue head = %s, want the detection signal", got.Id)
	}
}
