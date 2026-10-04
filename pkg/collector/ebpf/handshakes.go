package ebpf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// HandshakeLRU selects the LRU flavour of the scrub handshake maps.
type HandshakeLRU string

const (
	// HandshakeLRUAuto uses per-CPU LRU lists sized so each online CPU keeps
	// its share, unless that needs more than maxScrubHandshakeEntries, and
	// then the common LRU.
	HandshakeLRUAuto HandshakeLRU = "auto"
	// HandshakeLRUPerCPU always uses per-CPU lists, at most
	// maxScrubHandshakeEntries entries.
	HandshakeLRUPerCPU HandshakeLRU = "percpu"
	// HandshakeLRUCommon uses one LRU list shared by all CPUs.
	HandshakeLRUCommon HandshakeLRU = "common"
)

func ParseHandshakeLRU(s string) (HandshakeLRU, error) {
	switch HandshakeLRU(s) {
	case "":
		return HandshakeLRUAuto, nil
	case HandshakeLRUAuto, HandshakeLRUPerCPU, HandshakeLRUCommon:
		return HandshakeLRU(s), nil
	default:
		return "", fmt.Errorf("invalid scrub-handshake-lru %q (want auto|percpu|common)", s)
	}
}

const (
	// ScrubHandshakeEntries mirrors HANDSHAKES_MAP_SIZE: the entries the
	// online CPUs should be able to hold together.
	ScrubHandshakeEntries = 500000
	// Each entry preallocates ~100 bytes per family; past twice the base
	// size the common LRU's lock contention is the cheaper cost.
	maxScrubHandshakeEntries = 2 * ScrubHandshakeEntries

	// Approximate preallocated bytes per entry (key, value and htab element
	// overhead) of scrub_handshakes and scrub_handshakes_v6.
	handshakeEntryBytesV4 = 105
	handshakeEntryBytesV6 = 129
)

// HandshakeSizing is the scrub handshake map layout chosen at load time.
type HandshakeSizing struct {
	Entries  uint32 // max_entries of each of scrub_handshakes(_v6)
	PerCPU   bool   // BPF_F_NO_COMMON_LRU
	Possible int
	Online   int
	// OnlineErr is set when the online CPUs could not be counted and the
	// sizing assumed every possible CPU is online.
	OnlineErr error
}

// PerCPUShare is how many entries one CPU's LRU list holds; with per-CPU
// lists a CPU only ever evicts its own.
func (s HandshakeSizing) PerCPUShare() uint32 {
	if !s.PerCPU || s.Possible <= 0 {
		return s.Entries
	}
	return s.Entries / uint32(s.Possible)
}

// EstimatedBytes approximates the memory both handshake maps preallocate.
func (s HandshakeSizing) EstimatedBytes() uint64 {
	return uint64(s.Entries) * (handshakeEntryBytesV4 + handshakeEntryBytesV6)
}

// SizeScrubHandshakes sizes the per-CPU LRU so that the online CPUs, not the
// possible ones, share ScrubHandshakeEntries: the kernel splits max_entries
// evenly over every possible CPU and a CPU never borrows another's entries,
// so a VM with 128 possible and 8 online CPUs would otherwise track 31k.
func SizeScrubHandshakes(mode HandshakeLRU, possible, online int) HandshakeSizing {
	if possible < 1 {
		possible = 1
	}
	if online < 1 || online > possible {
		online = possible
	}
	s := HandshakeSizing{Possible: possible, Online: online}
	share := (ScrubHandshakeEntries + online - 1) / online
	need := share * possible
	switch {
	case mode == HandshakeLRUCommon || (mode != HandshakeLRUPerCPU && need > maxScrubHandshakeEntries):
		s.Entries = ScrubHandshakeEntries
	default:
		s.PerCPU = true
		// The kernel rounds max_entries down to a multiple of the possible
		// CPUs; do the same so Entries and PerCPUShare match the map.
		capped := max(maxScrubHandshakeEntries/possible, 1) * possible
		s.Entries = uint32(min(need, capped))
	}
	return s
}

// OnlineCPUs counts /sys/devices/system/cpu/online.
func OnlineCPUs() (int, error) {
	b, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return 0, err
	}
	return parseCPUList(strings.TrimSpace(string(b)))
}

// parseCPUList counts the CPUs in a kernel cpulist such as "0-3,8,10-11".
func parseCPUList(s string) (int, error) {
	n := 0
	for part := range strings.SplitSeq(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.Atoi(lo)
		if err != nil {
			return 0, fmt.Errorf("parse cpulist %q: %w", s, err)
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(hi); err != nil {
				return 0, fmt.Errorf("parse cpulist %q: %w", s, err)
			}
		}
		if last < first {
			return 0, fmt.Errorf("parse cpulist %q: bad range %q", s, part)
		}
		n += last - first + 1
	}
	return n, nil
}
