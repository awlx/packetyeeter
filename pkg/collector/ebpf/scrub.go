package ebpf

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// Scrub statistics layout, mirroring the SCRUB_* #defines in protector.bpf.c.
var (
	ScrubVerdictNames    = []string{"forward", "drop", "slow_path", "local"}
	ScrubFamilyNames     = []string{"ipv4", "ipv6", "other"}
	ScrubSlowReasonNames = []string{"no_neigh", "ttl", "mtu", "fib_fail", "egress_other", "vlan", "malformed", "not_fwded"}
)

const (
	scrubSlowBase     = 4 * 3
	scrubSlowReasons  = 8
	scrubSlowLimited  = scrubSlowBase + scrubSlowReasons
	scrubStatsSize    = scrubSlowLimited + 1
	ScrubSlowTTL      = 1
	ScrubSlowNotFwded = 7

	// LocalAddrsMax mirrors LOCAL_ADDRS_MAX in protector.bpf.c.
	LocalAddrsMax = 4096
)

// ScrubCounter mirrors struct scrub_counter in protector.bpf.c.
type ScrubCounter struct {
	Packets uint64
	Bytes   uint64
}

// ScrubStats is the scrub_stats map summed over CPUs.
type ScrubStats struct {
	Verdicts [4][3]ScrubCounter       // [verdict][family]
	SlowPath [scrubSlowReasons]uint64 // packets by slow-path reason
	// SlowLimited counts slow-path packets over -scrub-slow-path-pps
	// (dropped, or passed in monitor mode).
	SlowLimited uint64
}

// sumScrubStats folds per-CPU values, indexed like scrub_stats, into totals.
func sumScrubStats(perIndex [][]ScrubCounter) ScrubStats {
	var s ScrubStats
	for i, perCPU := range perIndex {
		var total ScrubCounter
		for _, v := range perCPU {
			total.Packets += v.Packets
			total.Bytes += v.Bytes
		}
		switch {
		case i < scrubSlowBase:
			s.Verdicts[i/3][i%3] = total
		case i < scrubSlowLimited:
			s.SlowPath[i-scrubSlowBase] = total.Packets
		case i == scrubSlowLimited:
			s.SlowLimited = total.Packets
		}
	}
	return s
}

func (m *Maps) ReadScrubStats() (ScrubStats, error) {
	if m.ScrubStats == nil {
		return ScrubStats{}, fmt.Errorf("scrub_stats map not loaded")
	}
	perIndex := make([][]ScrubCounter, scrubStatsSize)
	for i := range perIndex {
		if err := m.ScrubStats.Lookup(uint32(i), &perIndex[i]); err != nil {
			return ScrubStats{}, fmt.Errorf("read scrub_stats[%d]: %w", i, err)
		}
	}
	return sumScrubStats(perIndex), nil
}

// HasTxPort reports whether ifindex is a redirect target in tx_ports.
func (m *Maps) HasTxPort(ifindex int) (bool, error) {
	if m.TxPorts == nil {
		return false, fmt.Errorf("tx_ports map not loaded")
	}
	var v uint32
	if err := m.TxPorts.Lookup(uint32(ifindex), &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// splitLocalAddrs dedups addrs by family and reports an error if either
// family exceeds the local_addrs capacity.
func splitLocalAddrs(addrs []net.IP, capacity int) (map[[4]byte]struct{}, map[[16]byte]struct{}, error) {
	want4 := map[[4]byte]struct{}{}
	want6 := map[[16]byte]struct{}{}
	for _, ip := range addrs {
		if v4 := ip.To4(); v4 != nil {
			want4[[4]byte(v4)] = struct{}{}
		} else if v6 := ip.To16(); v6 != nil {
			want6[[16]byte(v6)] = struct{}{}
		}
	}
	var err error
	if len(want4) > capacity || len(want6) > capacity {
		err = fmt.Errorf("node has %d IPv4 and %d IPv6 addresses, local_addrs holds at most %d per family; "+
			"traffic to the excess addresses is not exempt from forwarding", len(want4), len(want6), capacity)
	}
	return want4, want6, err
}

// SyncLocalAddrs makes local_addrs_v4/v6 hold exactly addrs, as far as
// capacity allows.
func (m *Maps) SyncLocalAddrs(addrs []net.IP) error {
	if m.LocalAddrsV4 == nil || m.LocalAddrsV6 == nil {
		return fmt.Errorf("local_addrs maps not loaded")
	}
	want4, want6, capErr := splitLocalAddrs(addrs, LocalAddrsMax)

	var errs []string
	if capErr != nil {
		errs = append(errs, capErr.Error())
	}
	var k4 [4]byte
	var k6 [16]byte
	var v uint8
	var stale4 [][4]byte
	it := m.LocalAddrsV4.Iterate()
	for it.Next(&k4, &v) {
		if _, ok := want4[k4]; !ok {
			stale4 = append(stale4, k4)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate local_addrs_v4: %w", err)
	}
	var stale6 [][16]byte
	it6 := m.LocalAddrsV6.Iterate()
	for it6.Next(&k6, &v) {
		if _, ok := want6[k6]; !ok {
			stale6 = append(stale6, k6)
		}
	}
	if err := it6.Err(); err != nil {
		return fmt.Errorf("iterate local_addrs_v6: %w", err)
	}
	for _, k := range stale4 {
		if err := m.LocalAddrsV4.Delete(k); err != nil {
			errs = append(errs, fmt.Sprintf("delete %v: %v", net.IP(k[:]), err))
		}
	}
	for _, k := range stale6 {
		if err := m.LocalAddrsV6.Delete(k); err != nil {
			errs = append(errs, fmt.Sprintf("delete %v: %v", net.IP(k[:]), err))
		}
	}
	// Report failed adds as a count so a full map does not produce one
	// message per address.
	var addFailed int
	var firstAddErr error
	for k := range want4 {
		if err := m.LocalAddrsV4.Put(k, uint8(1)); err != nil {
			addFailed++
			firstAddErr = cmp.Or(firstAddErr, fmt.Errorf("add %v: %w", net.IP(k[:]), err))
		}
	}
	for k := range want6 {
		if err := m.LocalAddrsV6.Put(k, uint8(1)); err != nil {
			addFailed++
			firstAddErr = cmp.Or(firstAddErr, fmt.Errorf("add %v: %w", net.IP(k[:]), err))
		}
	}
	if addFailed > 0 {
		errs = append(errs, fmt.Sprintf("%d adds failed, first: %v", addFailed, firstAddErr))
	}
	if len(errs) > 0 {
		return fmt.Errorf("sync local_addrs: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ScrubMinKernel is the oldest kernel scrub mode supports: it needs BPF links
// for XDP (so a crashed collector detaches and the kernel keeps forwarding)
// and devmap lookups from XDP programs.
const ScrubMinKernel = "5.15"

// CheckKernelRelease returns an error if release (uname -r) is older than min.
func CheckKernelRelease(release, min string) error {
	have, err := majorMinor(release)
	if err != nil {
		return fmt.Errorf("parse kernel release %q: %w", release, err)
	}
	want, err := majorMinor(min)
	if err != nil {
		return err
	}
	if have[0] < want[0] || (have[0] == want[0] && have[1] < want[1]) {
		return fmt.Errorf("kernel %s is older than %s", release, min)
	}
	return nil
}

func majorMinor(v string) ([2]int, error) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return [2]int{}, fmt.Errorf("want major.minor")
	}
	minor := parts[1]
	if i := strings.IndexFunc(minor, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minor = minor[:i]
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return [2]int{}, err
	}
	mnr, err := strconv.Atoi(minor)
	if err != nil {
		return [2]int{}, err
	}
	return [2]int{maj, mnr}, nil
}
