package collector

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"
)

// legacyComputePPS is computePPS before prev state became sparse: it stored
// every source. Kept here as the reference the sparse version must match.
func legacyComputePPS(prev map[uint32]prevRate, ip uint32, rate ebpf.ICMPRate) float64 {
	pr, ok := prev[ip]
	prev[ip] = prevRate{lastTime: rate.LastTime, count: rate.Count}
	return ppsFromWindow(pr, ok, rate)
}

type floodOutcome struct {
	signal bool
	pps    float64 // only meaningful when signal
}

func outcome(pps float64) floodOutcome {
	if pps < rateMinFloodPPS {
		return floodOutcome{}
	}
	return floodOutcome{signal: true, pps: pps}
}

func TestSparsePrevRateMatchesLegacy(t *testing.T) {
	type sample struct{ t, count uint64 }
	cases := []struct {
		name string
		seq  []sample
	}{
		{"steady below", []sample{{1, 10}, {2, 20}, {3, 5}, {4, 900}}},
		{"steady above", []sample{{1, 1500}, {1, 1500}, {2, 2000}, {3, 2500}}},
		{"roll from above", []sample{{1, 5000}, {2, 10}, {3, 20}}},
		{"roll from below", []sample{{1, 999}, {2, 1}, {3, 998}}},
		{"roll from exactly threshold", []sample{{1, 1000}, {2, 3}}},
		{"rise across threshold then roll", []sample{{1, 500}, {1, 1200}, {2, 40}, {3, 40}}},
		{"drop below without roll then roll", []sample{{1, 3000}, {1, 900}, {2, 100}}},
		{"same window repeated", []sample{{5, 4000}, {5, 4000}, {5, 4000}}},
		{"clock goes backwards", []sample{{9, 2000}, {3, 10}, {2, 1500}}},
		{"zero window then flood", []sample{{1, 0}, {2, 0}, {3, 7000}, {4, 1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy := map[uint32]prevRate{}
			sparse := map[uint32]prevRate{}
			for i, s := range tc.seq {
				r := ebpf.ICMPRate{LastTime: s.t, Count: s.count}
				want := outcome(legacyComputePPS(legacy, 7, r))
				got := outcome(computePPS(sparse, 7, r))
				if got != want {
					t.Fatalf("step %d %+v: sparse %+v, legacy %+v", i, s, got, want)
				}
			}
		})
	}
}

// Random window sequences over a few sources, mixing sub- and super-threshold
// counts and frequent window rolls.
func TestSparsePrevRateMatchesLegacyRandom(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	counts := []uint64{0, 1, 500, 999, 1000, 1001, 4000, 100000}
	for run := 0; run < 2000; run++ {
		legacy := map[uint32]prevRate{}
		sparse := map[uint32]prevRate{}
		clock := map[uint32]uint64{}
		for step := 0; step < 40; step++ {
			ip := rng.Uint32N(4)
			switch rng.IntN(4) {
			case 0: // same window
			case 3: // rare backwards clock
				if clock[ip] > 0 {
					clock[ip]--
				}
			default:
				clock[ip] += uint64(1 + rng.IntN(3))
			}
			r := ebpf.ICMPRate{LastTime: clock[ip], Count: counts[rng.IntN(len(counts))]}
			if r.Count == 0 {
				continue // the pollers skip empty entries before computePPS
			}
			want := outcome(legacyComputePPS(legacy, ip, r))
			got := outcome(computePPS(sparse, ip, r))
			if got != want {
				t.Fatalf("run %d step %d ip %d %+v: sparse %+v, legacy %+v", run, step, ip, r, got, want)
			}
			for k, v := range sparse {
				if float64(v.count) < rateMinFloodPPS {
					t.Fatalf("sub-threshold source %d retained: %+v", k, v)
				}
				if legacy[k] != v {
					t.Fatalf("sparse state for %d = %+v, legacy %+v", k, v, legacy[k])
				}
			}
		}
	}
}

func TestSparsePrevRateV6DropsSubThreshold(t *testing.T) {
	prev := map[[16]byte]prevRate{}
	var k [16]byte
	k[0] = 0xfd
	computePPSV6(prev, k, ebpf.ICMPRate{LastTime: 1, Count: 2000})
	if _, ok := prev[k]; !ok {
		t.Fatal("flooding source not tracked")
	}
	computePPSV6(prev, k, ebpf.ICMPRate{LastTime: 1, Count: 10})
	if _, ok := prev[k]; ok {
		t.Fatal("sub-threshold source still tracked")
	}
}

// Prev maps no longer carry every source's timestamp, so stale pruning must
// still find "now" from the rate maps themselves.
func TestPruneStaleStateUsesRateClock(t *testing.T) {
	c := &Collector{
		prevICMPRates:      map[uint32]prevRate{1: {lastTime: 1, count: 5000}},
		prevUDPRates:       map[uint32]prevRate{},
		prevICMPRatesV6:    map[[16]byte]prevRate{},
		prevUDPRatesV6:     map[[16]byte]prevRate{},
		prevBadFlagsSeen:   map[uint32]uint64{},
		prevBadFlagsSeenV6: map[[16]byte]uint64{},
	}
	c.observeRateClock(prevStateStaleWindowNs + 10)
	c.pruneStaleState()
	if len(c.prevICMPRates) != 0 {
		t.Fatalf("stale flooding source survived pruning: %v", c.prevICMPRates)
	}
}

func TestEmitFloodSignalGateOrder(t *testing.T) {
	c := &Collector{signalQueue: make(chan *apiv1.Signal, 4)}
	c.allowedNets = parseAllowlist("192.0.2.0/24", logrus.New())
	allowed := net.IP{192, 0, 2, 1}
	other := net.IP{198, 51, 100, 1}
	for _, tc := range []struct {
		ip   net.IP
		pps  float64
		sent bool
	}{
		{allowed, 999, false},
		{allowed, 5000, false},
		{other, 999, false},
		{other, 1000, true},
	} {
		p, sent := c.emitFloodSignal(tc.ip, tc.pps, ebpf.ICMPRate{Count: uint64(tc.pps)}, apiv1.SignalType_SIGNAL_ICMP_FLOOD, "icmp")
		if sent != tc.sent || (sent && p != tc.pps) || (!sent && p != 0) {
			t.Fatalf("%s pps=%v: got (%v,%v), want sent=%v", tc.ip, tc.pps, p, sent, tc.sent)
		}
	}
	if len(c.signalQueue) != 1 {
		t.Fatalf("queued %d signals, want 1", len(c.signalQueue))
	}
}

func TestEmitFloodSignalSubThresholdAllocFree(t *testing.T) {
	c := &Collector{signalQueue: make(chan *apiv1.Signal, 1)}
	c.allowedNets = parseAllowlist("192.0.2.0/24,2001:db8::/32", logrus.New())
	ip := net.IP{198, 51, 100, 1}
	allocs := testing.AllocsPerRun(100, func() {
		c.emitFloodSignal(ip, 3, ebpf.ICMPRate{Count: 3}, apiv1.SignalType_SIGNAL_ICMP_FLOOD, "icmp")
	})
	if allocs != 0 {
		t.Fatalf("sub-threshold emitFloodSignal allocated %v times", allocs)
	}
}

func TestWarnMapWalkRateLimited(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	c := &Collector{Logger: l}
	err := errors.New("iteration aborted")
	for i := 0; i < 5; i++ {
		c.warnMapWalk("Failed to walk IPv4 ICMP rate map", err)
		c.warnMapWalk("Failed to walk IPv4 UDP rate map", err)
	}
	if n := strings.Count(buf.String(), "level=warning"); n != 2 {
		t.Fatalf("logged %d warnings for 10 failures over 2 maps, want 2:\n%s", n, buf.String())
	}
	l0 := c.walkErrLogged["Failed to walk IPv4 ICMP rate map"]
	l0.at = l0.at.Add(-walkErrLogInterval)
	c.walkErrLogged["Failed to walk IPv4 ICMP rate map"] = l0
	buf.Reset()
	c.warnMapWalk("Failed to walk IPv4 ICMP rate map", err)
	if !strings.Contains(buf.String(), "suppressed=4") {
		t.Fatalf("want suppressed count after interval, got:\n%s", buf.String())
	}
}
