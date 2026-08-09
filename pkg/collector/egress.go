package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/metrics"
)

const (
	// egressMaxBatchSize caps how many egress volume signals one poll may emit,
	// mirroring rateMaxBatchSize for the flood readers. Without it a large
	// client population would turn a single poll into an unbounded burst on the
	// signal queue, which drops oldest-first and would starve flood signals.
	egressMaxBatchSize = 1000

	// egressPrevStateHardCap bounds the userspace shadow map. The kernel map is
	// LRU and self-bounding; this map is a plain Go map and is not, so it needs
	// its own ceiling for the same reason prevStateHardCap exists.
	egressPrevStateHardCap = 1 << 18

	// egressPrevStateTTL is how long a client with no further egress is kept in
	// the shadow map. It must comfortably exceed the analyzer's detection
	// window so a client that pauses mid-window is not treated as new (and
	// therefore credited with its whole cumulative counter) when it resumes.
	egressPrevStateTTL = 15 * time.Minute
)

// prevEgress is the last cumulative counter observed for one client, plus when
// it was observed, so stale entries can be pruned on wall-clock time. The
// kernel counter itself carries no timestamp.
type prevEgress struct {
	bytes    uint64
	lastSeen time.Time
}

// sendEgressVolume diffs the eBPF egress byte counters and emits one
// SIGNAL_EGRESS_VOLUME per client that moved a meaningful amount of data since
// the previous poll.
//
// The kernel counters are cumulative and monotonic, so the delta is what
// matters. Two things can make the counter appear to go backwards: LRU eviction
// followed by reinsertion, and a collector restart. Both are treated as "this
// is a fresh counter", crediting the client with the current value rather than
// a negative or absurdly large delta.
//
// Clients seen for the first time are recorded but NOT credited. Their counter
// may have been accumulating since long before the collector started watching,
// so emitting it as a single-interval delta would report a rate that never
// happened.
func (c *Collector) sendEgressVolume() {
	if c.Maps == nil {
		return
	}
	if !c.Config.EgressAccounting {
		return
	}

	now := time.Now()
	window := c.Config.PollInterval
	if window <= 0 {
		window = time.Second
	}
	windowSeconds := window.Seconds()

	sent := 0
	var totalBytes uint64

	if c.Maps.EgressBytes != nil {
		var key uint32
		var total uint64
		iter := c.Maps.EgressBytes.Iterate()
		for iter.Next(&key, &total) {
			if sent >= egressMaxBatchSize {
				break
			}
			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, key)
			delta, ok := deltaEgress(c.prevEgressBytes, key, total, now)
			if !ok {
				continue
			}
			if c.emitEgressSignal(net.IP(ipBytes), delta, total, windowSeconds) {
				totalBytes += delta
				sent++
			}
		}
	}

	// IPv6 carries its own per-poll budget so a large IPv4 client population
	// cannot starve IPv6 emission on the same poll.
	sentV6 := 0
	if c.Maps.EgressBytesV6 != nil {
		var key [16]byte
		var total uint64
		iter := c.Maps.EgressBytesV6.Iterate()
		for iter.Next(&key, &total) {
			if sentV6 >= egressMaxBatchSize {
				break
			}
			delta, ok := deltaEgress(c.prevEgressBytesV6, key, total, now)
			if !ok {
				continue
			}
			if c.emitEgressSignal(net.IP(key[:]), delta, total, windowSeconds) {
				totalBytes += delta
				sentV6++
			}
		}
	}

	if n := sent + sentV6; n > 0 {
		if metrics.EgressVolumeSignals != nil {
			metrics.EgressVolumeSignals.Add(float64(n))
		}
		if metrics.EgressBytesReported != nil {
			metrics.EgressBytesReported.Add(float64(totalBytes))
		}
		c.Logger.WithFields(map[string]interface{}{
			"count": n,
			"bytes": totalBytes,
		}).Debug("Sent egress volume signals")
	}
}

// deltaEgress updates the shadow map for one client and reports how many bytes
// it moved since the previous poll. ok is false when nothing should be emitted:
// the client is newly observed, or its counter did not advance.
func deltaEgress[K comparable](m map[K]prevEgress, key K, total uint64, now time.Time) (uint64, bool) {
	prev, seen := m[key]
	m[key] = prevEgress{bytes: total, lastSeen: now}

	if !seen {
		return 0, false
	}
	if total < prev.bytes {
		// Counter went backwards: LRU eviction and reinsertion, so the current
		// value is all the traffic there has been since it reappeared.
		return total, total > 0
	}
	delta := total - prev.bytes
	return delta, delta > 0
}

// emitEgressSignal applies the allowlist and volume floor and, if the client
// qualifies, sends one egress volume signal. It returns whether a signal was
// sent so the v4 and v6 callers cannot drift apart in their gating.
func (c *Collector) emitEgressSignal(ip net.IP, delta, total uint64, windowSeconds float64) bool {
	if c.checkAllowlist(ip) {
		return false
	}
	if delta < c.Config.EgressMinBytes {
		return false
	}

	bytesPerSecond := float64(delta)
	if windowSeconds > 0 {
		bytesPerSecond = float64(delta) / windowSeconds
	}

	// sendSignal only enqueues; the sender goroutine marshals later. The v6
	// iterator reuses one key array per poll, so storing that slice directly
	// would let the address change out from under a queued signal and attribute
	// the bytes to whichever client was iterated last.
	addr := append(net.IP(nil), ip...)

	c.sendSignal(&apiv1.Signal{
		Id:        fmt.Sprintf("egress-%s-%d", addr.String(), total),
		Timestamp: timestamppb.Now(),
		Type:      apiv1.SignalType_SIGNAL_EGRESS_VOLUME,
		Source:    apiv1.SignalSource_SOURCE_EBPF,
		Ip:        addr,
		Weight:    bytesPerSecond,
		EgressContext: &apiv1.EgressContext{
			BytesDelta:    delta,
			BytesTotal:    total,
			WindowSeconds: windowSeconds,
		},
	})
	return true
}

// pruneEgressState drops clients that have stopped transmitting. The kernel
// maps are LRU and bound themselves; these Go maps are not.
func (c *Collector) pruneEgressState(now time.Time) {
	prunePrevEgressMap(c.prevEgressBytes, now)
	prunePrevEgressMap(c.prevEgressBytesV6, now)
}

func prunePrevEgressMap[K comparable](m map[K]prevEgress, now time.Time) {
	cutoff := now.Add(-egressPrevStateTTL)
	for k, v := range m {
		if v.lastSeen.Before(cutoff) {
			delete(m, k)
		}
	}
	if len(m) > egressPrevStateHardCap {
		// Clearing rather than partially evicting keeps this O(n) and
		// predictable. The cost of a reset is that every surviving client is
		// treated as newly observed for one poll, which suppresses one
		// interval of signals rather than inventing a false one.
		for k := range m {
			delete(m, k)
		}
	}
}
