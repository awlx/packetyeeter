package ebpf

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// Mirrors of the fingerprint layout in protector.bpf.c.
const (
	FingerprintMapSize          = 65536
	configKeyFingerprint uint32 = 6
	fingerprintBatch            = 4096
)

// FingerprintKey mirrors struct fp_key.
type FingerprintKey struct {
	Dst        [16]byte // IPv4 in the first 4 bytes
	SrcNet     [8]byte  // source /24 or /48
	DstPort    uint16   // 0 when not TCP/UDP or a later fragment
	Proto      uint8
	SizeBucket uint8
	TTLBucket  uint8
	Dropped    uint8
	Family     uint8 // 0 IPv4, 1 IPv6
	Pad        uint8
}

// DstIP returns the destination as a 4- or 16-byte address.
func (k FingerprintKey) DstIP() net.IP {
	if k.Family == 0 {
		return append(net.IP(nil), k.Dst[:4]...)
	}
	return append(net.IP(nil), k.Dst[:]...)
}

// SrcNetIP returns the source network address, 4 or 16 bytes long.
func (k FingerprintKey) SrcNetIP() net.IP {
	if k.Family == 0 {
		return append(net.IP(nil), k.SrcNet[:4]...)
	}
	ip := make(net.IP, net.IPv6len)
	copy(ip, k.SrcNet[:])
	return ip
}

// Fingerprint is one bucket summed over CPUs.
type Fingerprint struct {
	Key     FingerprintKey
	Packets uint64
	Bytes   uint64
}

// fpOverflow mirrors struct fp_overflow.
type fpOverflow struct {
	Packets uint64
	FullGen uint32
	Pad     uint32
}

// FingerprintSizeBucket and the helpers below are the BPF bucket math, so
// tests and consumers can compute the bucket a packet lands in.
func FingerprintSizeBucket(ipTotalLen uint16) uint8 {
	switch {
	case ipTotalLen < 128:
		return 0
	case ipTotalLen < 256:
		return 1
	case ipTotalLen < 512:
		return 2
	case ipTotalLen < 1024:
		return 3
	}
	return 4
}

func FingerprintTTLBucket(ttl uint8) uint8 { return ttl >> 5 }

// FingerprintSrcNet returns the /24 (IPv4) or /48 (IPv6) network of src.
func FingerprintSrcNet(src net.IP) net.IP {
	if v4 := src.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32))
	}
	return src.To16().Mask(net.CIDRMask(48, 128))
}

// fingerprintMap returns the map XDP fills while gen is active.
func (m *Maps) fingerprintMap(gen uint32) *ebpf.Map {
	if gen&1 == 1 {
		return m.FingerprintsA
	}
	return m.FingerprintsB
}

// SetFingerprintGeneration makes XDP count into the map selected by gen's
// parity (odd: fingerprints_a); 0 turns fingerprinting off.
func (m *Maps) SetFingerprintGeneration(gen uint32) error {
	if m.ConfigMap == nil {
		return errors.New("config_map not loaded")
	}
	return m.ConfigMap.Put(configKeyFingerprint, gen)
}

// DrainFingerprints reads and deletes every entry of the map gen selects.
// The caller must have moved XDP to another generation first.
func (m *Maps) DrainFingerprints(gen uint32) ([]Fingerprint, error) {
	fm := m.fingerprintMap(gen)
	if fm == nil {
		return nil, errors.New("fingerprint maps not loaded")
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	return drainFingerprints(ciliumDrainMap{fm}, cpus)
}

type drainMap interface {
	BatchLookupAndDelete(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error)
	Delete(key any) error
	iterate() entryIterator
	String() string
}

type ciliumDrainMap struct{ *ebpf.Map }

func (m ciliumDrainMap) iterate() entryIterator { return m.Map.Iterate() }

func drainFingerprints(fm drainMap, cpus int) ([]Fingerprint, error) {
	keys := make([]FingerprintKey, fingerprintBatch)
	vals := make([]ScrubCounter, fingerprintBatch*cpus)
	var out []Fingerprint
	var cursor ebpf.MapBatchCursor
	for first := true; ; first = false {
		n, err := fm.BatchLookupAndDelete(&cursor, keys, vals, nil)
		if first && errors.Is(err, ebpf.ErrNotSupported) {
			// Batch map ops need Linux 5.6+.
			return drainFingerprintsIter(fm)
		}
		out = append(out, sumFingerprints(keys[:n], vals[:n*cpus], cpus)...)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("drain %s: %w", fm, err)
		}
	}
}

// drainFingerprintsIter reads every entry, then deletes the keys it read:
// deleting during iteration can make the iterator restart or skip keys.
func drainFingerprintsIter(fm drainMap) ([]Fingerprint, error) {
	var (
		k      FingerprintKey
		perCPU []ScrubCounter
		keys   []FingerprintKey
		out    []Fingerprint
	)
	it := fm.iterate()
	for it.Next(&k, &perCPU) {
		keys = append(keys, k)
		out = append(out, sumFingerprints([]FingerprintKey{k}, perCPU, len(perCPU))...)
	}
	// Delete what was read even if iteration failed: those entries are
	// returned now and must not be reported again. The caller retries the
	// rest before XDP writes to this map again.
	var iterErr, delErr error
	if err := it.Err(); err != nil {
		iterErr = fmt.Errorf("iterate %s: %w", fm, err)
	}
	for i := range keys {
		if err := fm.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) && delErr == nil {
			delErr = fmt.Errorf("delete from %s: %w", fm, err)
		}
	}
	return out, errors.Join(iterErr, delErr)
}

// sumFingerprints folds per-CPU values (cpus consecutive values per key).
func sumFingerprints(keys []FingerprintKey, perCPU []ScrubCounter, cpus int) []Fingerprint {
	out := make([]Fingerprint, 0, len(keys))
	for i, k := range keys {
		fp := Fingerprint{Key: k}
		for _, v := range perCPU[i*cpus : (i+1)*cpus] {
			fp.Packets += v.Packets
			fp.Bytes += v.Bytes
		}
		if fp.Packets > 0 {
			out = append(out, fp)
		}
	}
	return out
}

// FingerprintOverflow returns the packets not fingerprinted because the
// active map was full (or an insert failed), summed over CPUs.
func (m *Maps) FingerprintOverflow() (uint64, error) {
	if m.FPOverflow == nil {
		return 0, errors.New("fingerprint_overflow map not loaded")
	}
	var perCPU []fpOverflow
	if err := m.FPOverflow.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("read fingerprint_overflow: %w", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v.Packets
	}
	return total, nil
}
