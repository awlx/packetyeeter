package collector

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	DefaultFingerprintInterval = 10 * time.Second
	DefaultFingerprintTop      = 32
	// fingerprintMaxDestinations bounds the signals per interval to
	// top × this, well under the default signal queue size.
	fingerprintMaxDestinations = 256
	// fingerprintSettle lets packets that read the old generation finish
	// their map update before the map is drained.
	fingerprintSettle = 50 * time.Millisecond
)

type fingerprintStore interface {
	SetFingerprintGeneration(gen uint32) error
	DrainFingerprints(gen uint32) ([]ebpf.Fingerprint, error)
}

// fingerprinter alternates XDP between the two fingerprint maps, so one is
// only read once XDP has stopped writing to it.
type fingerprinter struct {
	store  fingerprintStore
	gen    uint32
	since  time.Time
	settle time.Duration
	sleep  func(time.Duration)
	now    func() time.Time
}

func newFingerprinter(store fingerprintStore) *fingerprinter {
	return &fingerprinter{store: store, settle: fingerprintSettle, sleep: time.Sleep, now: time.Now}
}

func (f *fingerprinter) start() error {
	if err := f.store.SetFingerprintGeneration(1); err != nil {
		return err
	}
	f.gen = 1
	f.since = f.now()
	return nil
}

// nextGeneration skips 0 (off) and keeps the parity alternating across the
// wrap, so the next generation always selects the other map.
func nextGeneration(gen uint32) uint32 {
	next := gen + 1
	if next == 0 {
		next = 2
	}
	return next
}

// flip switches XDP to the other map and returns what the previous one
// collected, and over how long.
func (f *fingerprinter) flip() ([]ebpf.Fingerprint, time.Duration, error) {
	old := f.gen
	next := nextGeneration(old)
	if err := f.store.SetFingerprintGeneration(next); err != nil {
		return nil, 0, fmt.Errorf("switch fingerprint map: %w", err)
	}
	f.gen = next
	now := f.now()
	elapsed := now.Sub(f.since)
	f.since = now
	f.sleep(f.settle)
	fps, err := f.store.DrainFingerprints(old)
	return fps, elapsed, err
}

type fingerprintCut struct {
	buckets      int
	destinations int
}

type fpDest struct {
	key     [17]byte // family + address
	packets uint64
	buckets []ebpf.Fingerprint
}

// selectTopFingerprints keeps the top buckets by packets for each of the
// busiest maxDst destinations. Buckets of dropped destinations count as cut
// buckets too.
func selectTopFingerprints(fps []ebpf.Fingerprint, top, maxDst int) ([]ebpf.Fingerprint, fingerprintCut) {
	byDst := map[[17]byte]*fpDest{}
	var dests []*fpDest
	for _, fp := range fps {
		var k [17]byte
		k[0] = fp.Key.Family
		copy(k[1:], fp.Key.Dst[:])
		d := byDst[k]
		if d == nil {
			d = &fpDest{key: k}
			byDst[k] = d
			dests = append(dests, d)
		}
		d.packets += fp.Packets
		d.buckets = append(d.buckets, fp)
	}
	// Ties are broken on the key so the result does not depend on map order.
	slices.SortFunc(dests, func(a, b *fpDest) int {
		if c := cmp.Compare(b.packets, a.packets); c != 0 {
			return c
		}
		return bytes.Compare(a.key[:], b.key[:])
	})

	var cut fingerprintCut
	if len(dests) > maxDst {
		for _, d := range dests[maxDst:] {
			cut.buckets += len(d.buckets)
		}
		cut.destinations = len(dests) - maxDst
		dests = dests[:maxDst]
	}
	var kept []ebpf.Fingerprint
	for _, d := range dests {
		slices.SortFunc(d.buckets, compareFingerprints)
		if len(d.buckets) > top {
			cut.buckets += len(d.buckets) - top
			d.buckets = d.buckets[:top]
		}
		kept = append(kept, d.buckets...)
	}
	return kept, cut
}

func compareFingerprints(a, b ebpf.Fingerprint) int {
	if c := cmp.Compare(b.Packets, a.Packets); c != 0 {
		return c
	}
	if c := cmp.Compare(b.Bytes, a.Bytes); c != 0 {
		return c
	}
	ka, kb := a.Key, b.Key
	return cmp.Or(
		bytes.Compare(ka.SrcNet[:], kb.SrcNet[:]),
		cmp.Compare(ka.Proto, kb.Proto),
		cmp.Compare(ka.DstPort, kb.DstPort),
		cmp.Compare(ka.SizeBucket, kb.SizeBucket),
		cmp.Compare(ka.TTLBucket, kb.TTLBucket),
		cmp.Compare(ka.Dropped, kb.Dropped),
	)
}

func fingerprintSignal(collectorID string, fp ebpf.Fingerprint, interval time.Duration, now time.Time, seq int) *apiv1.Signal {
	secs := uint32(interval.Round(time.Second) / time.Second)
	if secs == 0 {
		secs = 1
	}
	return &apiv1.Signal{
		Id:        fmt.Sprintf("fingerprint-%d-%d", now.UnixNano(), seq),
		Timestamp: timestamppb.New(now),
		Type:      apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT,
		Source:    apiv1.SignalSource_SOURCE_EBPF,
		// Ip stays empty: analyzers without fingerprint support drop such
		// signals instead of scoring them.
		Fingerprint: &apiv1.ScrubFingerprint{
			CollectorId:     collectorID,
			DstIp:           fp.Key.DstIP(),
			Protocol:        uint32(fp.Key.Proto),
			DstPort:         uint32(fp.Key.DstPort),
			SizeBucket:      uint32(fp.Key.SizeBucket),
			TtlBucket:       uint32(fp.Key.TTLBucket),
			SrcNet:          fp.Key.SrcNetIP(),
			Dropped:         fp.Key.Dropped != 0,
			Packets:         fp.Packets,
			Bytes:           fp.Bytes,
			IntervalSeconds: secs,
		},
	}
}

func (c *Collector) runFingerprints() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.Config.FingerprintInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.flushFingerprints()
		}
	}
}

func (c *Collector) flushFingerprints() {
	fps, elapsed, err := c.fingerprints.flip()
	if err != nil {
		// A partial drain still yields what it read; the rest is reported
		// with a later interval.
		c.Logger.WithError(err).Warn("Failed to read scrub fingerprints")
		if len(fps) == 0 {
			return
		}
	}
	metrics.ScrubFingerprintBuckets.Set(float64(len(fps)))
	kept, cut := selectTopFingerprints(fps, c.Config.FingerprintTop, fingerprintMaxDestinations)
	metrics.ScrubFingerprintCapped.WithLabelValues("bucket").Add(float64(cut.buckets))
	metrics.ScrubFingerprintCapped.WithLabelValues("destination").Add(float64(cut.destinations))
	// The sender discards signals while disconnected anyway.
	if !c.connected.Load() {
		return
	}
	now := time.Now()
	for i, fp := range kept {
		c.offerSignal(fingerprintSignal(c.collectorID, fp, elapsed, now, i))
	}
}

// offerSignal enqueues without evicting older signals: a burst of telemetry
// must not push detection signals out of a full queue.
func (c *Collector) offerSignal(signal *apiv1.Signal) {
	select {
	case c.signalQueue <- signal:
		c.recordSignalQueued()
	default:
		c.recordSignalDrop()
	}
}

// fingerprintOverflowMetric reads the kernel counter at scrape time.
type fingerprintOverflowMetric struct {
	read   func() (uint64, error)
	logger *logrus.Logger
}

func (m *fingerprintOverflowMetric) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.ScrubFingerprintOverflowDesc
}

func (m *fingerprintOverflowMetric) Collect(ch chan<- prometheus.Metric) {
	n, err := m.read()
	if err != nil {
		m.logger.WithError(err).Warn("Failed to read fingerprint overflow counter")
		return
	}
	ch <- prometheus.MustNewConstMetric(metrics.ScrubFingerprintOverflowDesc, prometheus.CounterValue, float64(n))
}
