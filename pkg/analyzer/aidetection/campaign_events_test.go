package aidetection

import (
	"fmt"
	"math/rand/v2"
	"net"
	"reflect"
	"testing"
	"time"
)

func ringValues(r *eventRing[int]) []int {
	out := make([]int, 0, r.Len())
	for i := range r.Len() {
		out = append(out, *r.At(i))
	}
	return out
}

func TestEventRingOrderAfterWrap(t *testing.T) {
	r := newEventRing[int](4)
	for v := 1; v <= 10; v++ {
		r.PushBack(v)
	}
	if got, want := ringValues(&r), []int{7, 8, 9, 10}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ring = %v, want %v", got, want)
	}
	if got, want := r.Slice(), []int{7, 8, 9, 10}; !reflect.DeepEqual(got, want) {
		t.Fatalf("slice = %v, want %v", got, want)
	}
}

func TestEventRingExactCapacity(t *testing.T) {
	r := newEventRing[int](5)
	for v := 1; v <= 5; v++ {
		r.PushBack(v)
	}
	if got, want := ringValues(&r), []int{1, 2, 3, 4, 5}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ring at capacity = %v, want %v", got, want)
	}
	if len(r.buf) != 5 {
		t.Fatalf("buffer length = %d, want 5", len(r.buf))
	}
	r.PushBack(6)
	if got, want := ringValues(&r), []int{2, 3, 4, 5, 6}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ring after one more push = %v, want %v", got, want)
	}
}

func TestEventRingDropFrontAfterWrap(t *testing.T) {
	r := newEventRing[int](4)
	for v := 1; v <= 6; v++ {
		r.PushBack(v)
	}
	r.DropFront(3)
	if got, want := ringValues(&r), []int{6}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ring = %v, want %v", got, want)
	}
	r.PushBack(7)
	r.PushBack(8)
	if got, want := ringValues(&r), []int{6, 7, 8}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ring = %v, want %v", got, want)
	}
}

func campaignTestEvent(ts time.Time, id int) campaignSignal {
	return campaignSignal{
		signalType: SignalUDPFlood,
		source:     SourceUDP,
		ip:         net.IPv4(198, 51, 100, byte(id%250+1)),
		timestamp:  ts,
		destIP:     fmt.Sprintf("203.0.113.%d", id%250+1),
		destSubnet: "203.0.113.0/24",
		dstPort:    uint32(id%64 + 1),
		collector:  fmt.Sprintf("c%d", id%3),
		weight:     1,
	}
}

func TestCampaignEventsPruneAfterWrap(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	events := newCampaignEvents(4)
	for i := range 9 {
		events.Push(campaignTestEvent(base.Add(time.Duration(i)*time.Second), i))
		events.TrimTo(4)
	}
	firstSeen, lastSeen, ok := events.PruneBefore(base.Add(7 * time.Second))
	if !ok {
		t.Fatal("prune removed every event")
	}
	if !firstSeen.Equal(base.Add(7*time.Second)) || !lastSeen.Equal(base.Add(8*time.Second)) {
		t.Fatalf("firstSeen=%v lastSeen=%v", firstSeen, lastSeen)
	}
	if events.Len() != 2 || events.At(0).dstPort != 8 || events.At(1).dstPort != 9 {
		t.Fatalf("unexpected events after prune: len=%d", events.Len())
	}
}

type sliceCampaignModel struct {
	events    []campaignSignal
	firstSeen time.Time
	lastSeen  time.Time
	maxEvents int
	window    time.Duration
}

func (m *sliceCampaignModel) record(ev campaignSignal) {
	if m.firstSeen.IsZero() || ev.timestamp.Before(m.firstSeen) {
		m.firstSeen = ev.timestamp
	}
	if ev.timestamp.After(m.lastSeen) {
		m.lastSeen = ev.timestamp
	}
	m.events = append(m.events, ev)
	m.prune(ev.timestamp)
	if excess := len(m.events) - m.maxEvents; excess > 0 {
		copy(m.events, m.events[excess:])
		m.events = m.events[:m.maxEvents]
	}
}

func (m *sliceCampaignModel) prune(now time.Time) {
	cutoff := now.Add(-m.window)
	if len(m.events) == 0 || !m.firstSeen.Before(cutoff) {
		return
	}
	kept := m.events[:0]
	for _, ev := range m.events {
		if !ev.timestamp.Before(cutoff) {
			kept = append(kept, ev)
		}
	}
	m.events = kept
	if len(m.events) == 0 {
		return
	}
	m.firstSeen = m.events[0].timestamp
	m.lastSeen = m.events[0].timestamp
	for _, ev := range m.events[1:] {
		if ev.timestamp.Before(m.firstSeen) {
			m.firstSeen = ev.timestamp
		}
		if ev.timestamp.After(m.lastSeen) {
			m.lastSeen = ev.timestamp
		}
	}
}

func modelCampaign(m *sliceCampaignModel, key string, episode uint64) *attackCampaign {
	c := &attackCampaign{
		key:       key,
		vector:    SignalUDPFlood,
		firstSeen: m.firstSeen,
		lastSeen:  m.lastSeen,
		events:    newCampaignEvents(len(m.events) + 1),
		episode:   episode,
	}
	for _, ev := range m.events {
		c.events.Push(ev)
	}
	return c
}

func TestCampaignEventsMatchSliceModel(t *testing.T) {
	const window = 10 * time.Second
	for seed := range uint64(40) {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
			maxEvents := 1 + rng.IntN(48)
			agg := NewCampaignAggregator(CampaignConfig{
				Window:     window,
				MaxEvents:  maxEvents,
				MinSignals: 1,
				MinDestIPs: 2,
			})
			model := &sliceCampaignModel{maxEvents: maxEvents, window: window}
			const key = "vector=udp_flood|source=udp|collector=c0|dest_subnet=203.0.113.0/24"
			clock := time.Unix(1_700_000_000, 0)
			disorder := time.Duration(rng.IntN(3000)) * time.Millisecond

			for step := range 2000 {
				clock = clock.Add(time.Duration(rng.IntN(400)) * time.Millisecond)
				ts := clock
				switch roll := rng.IntN(100); {
				case roll < 30:
					ts = clock.Add(-time.Duration(rng.Int64N(int64(disorder) + 1)))
				case roll < 32:
					ts = clock.Add(-time.Duration(rng.IntN(20)) * time.Second)
				case roll < 34:
					ts = clock.Add(time.Duration(rng.IntN(5)) * time.Second)
				}
				ev := campaignTestEvent(ts, step)

				agg.recordLocked(key, ev)
				model.record(ev)
				c := agg.campaigns[key]

				if rng.IntN(10) == 0 {
					now := clock.Add(time.Duration(rng.IntN(15)) * time.Second)
					agg.pruneCampaignLocked(c, now)
					model.prune(now)
				}

				assertCampaignMatchesModel(t, step, agg, c, model)
			}
		})
	}
}

func assertCampaignMatchesModel(t *testing.T, step int, agg *CampaignAggregator, c *attackCampaign, model *sliceCampaignModel) {
	t.Helper()
	if c.events.Len() != len(model.events) {
		t.Fatalf("step %d: len=%d, model len=%d", step, c.events.Len(), len(model.events))
	}
	for i, want := range model.events {
		if got := *c.events.At(i); !reflect.DeepEqual(got, want) {
			t.Fatalf("step %d: event %d = %+v, model %+v", step, i, got, want)
		}
	}
	if !c.firstSeen.Equal(model.firstSeen) || !c.lastSeen.Equal(model.lastSeen) {
		t.Fatalf("step %d: firstSeen=%v lastSeen=%v, model firstSeen=%v lastSeen=%v",
			step, c.firstSeen, c.lastSeen, model.firstSeen, model.lastSeen)
	}
	got, gotOK := agg.evaluateCampaignLocked(c)
	want, wantOK := agg.evaluateCampaignLocked(modelCampaign(model, c.key, c.episode))
	if gotOK != wantOK || !reflect.DeepEqual(got, want) {
		t.Fatalf("step %d: detection %+v (%v), model %+v (%v)", step, got, gotOK, want, wantOK)
	}
}

func TestEventHistoryOrderAndCleanupAfterWrap(t *testing.T) {
	h := NewEventHistory(3, time.Minute)
	base := time.Now().Add(-30 * time.Minute)
	for i := range 5 {
		h.AddEvent(SignalEvent{Timestamp: base.Add(time.Duration(i) * time.Minute)})
	}
	snapshot := h.GetSnapshot()
	want := []time.Time{base.Add(2 * time.Minute), base.Add(3 * time.Minute), base.Add(4 * time.Minute)}
	if !reflect.DeepEqual(snapshot.Timestamps, want) {
		t.Fatalf("timestamps = %v, want %v", snapshot.Timestamps, want)
	}
	if len(snapshot.Events) != 3 || !snapshot.Events[0].Timestamp.Equal(want[0]) {
		t.Fatalf("events out of order: %+v", snapshot.Events)
	}

	h.mu.Lock()
	h.cleanupOldEventsLocked(base.Add(time.Minute + 3*time.Minute + 30*time.Second))
	h.mu.Unlock()
	if got := h.GetSnapshot().Timestamps; !reflect.DeepEqual(got, want[2:]) {
		t.Fatalf("timestamps after cleanup = %v, want %v", got, want[2:])
	}
}

func legacyDestinationIdentity(raw string) (string, string) {
	if raw == "" {
		return "", "unknown"
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", "unknown"
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip.String(), (&net.IPNet{IP: net.IPv4(ip4[0], ip4[1], ip4[2], 0), Mask: net.CIDRMask(24, 32)}).String()
	}
	subnetIP := make(net.IP, net.IPv6len)
	copy(subnetIP, ip.To16())
	clear(subnetIP[8:])
	return ip.String(), (&net.IPNet{IP: subnetIP, Mask: net.CIDRMask(64, 128)}).String()
}

func TestDestinationIdentityMatchesNetParsing(t *testing.T) {
	inputs := []string{
		"", "203.0.113.7", "::ffff:203.0.113.7", "2001:db8:1:2:3:4:5:6", "2001:db8::1",
		"::1", "::", "::1.2.3.4", "fe80::1%eth0", "010.0.0.1", "not-an-ip", "1.2.3.256",
		"0.0.0.0", "255.255.255.255", "2001:0db8:0000:0000:0000:ff00:0042:8329",
	}
	for _, raw := range inputs {
		gotIP, gotSubnet := destinationIdentity(map[string]interface{}{"dest_ip": raw})
		wantIP, wantSubnet := legacyDestinationIdentity(raw)
		if gotIP != wantIP || gotSubnet != wantSubnet {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", raw, gotIP, gotSubnet, wantIP, wantSubnet)
		}
	}
}

func TestCampaignKeyMatchesFormat(t *testing.T) {
	for _, subnet := range []string{"", "any", "203.0.113.0/24"} {
		got := campaignKey(SignalUDPFlood, SourceUDP, "c1", subnet)
		want := subnet
		if want == "" {
			want = "unknown"
		}
		want = fmt.Sprintf("vector=%s|source=%s|collector=%s|dest_subnet=%s", SignalUDPFlood, SourceUDP, "c1", want)
		if got != want {
			t.Errorf("campaignKey(%q) = %q, want %q", subnet, got, want)
		}
	}
}
