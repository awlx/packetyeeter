package ebpf

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/cilium/ebpf"
)

// SynCookieMode selects when xdp_scrub challenges SYNs from unverified sources.
type SynCookieMode string

const (
	SynCookiesOff SynCookieMode = "off"
	// SynCookiesAuto challenges only destinations whose SYN rate is over
	// the threshold.
	SynCookiesAuto SynCookieMode = "auto"
	SynCookiesOn   SynCookieMode = "on"
)

func ParseSynCookieMode(s string) (SynCookieMode, error) {
	switch SynCookieMode(s) {
	case "", SynCookiesOff:
		return SynCookiesOff, nil
	case SynCookiesAuto, SynCookiesOn:
		return SynCookieMode(s), nil
	default:
		return "", fmt.Errorf("invalid scrub-syn-cookies %q (want off|auto|on)", s)
	}
}

// SynCookieStyle selects how a source proves it receives packets.
type SynCookieStyle string

const (
	// SynCookieStyleOOS sends an out-of-sequence SYN-ACK; the client answers
	// with a RST and its SYN retransmission passes.
	SynCookieStyleOOS SynCookieStyle = "oos"
	// SynCookieStyleReset sends a valid SYN-ACK; the client's ACK proves the
	// source and the node resets that connection.
	SynCookieStyleReset SynCookieStyle = "reset"
)

func ParseSynCookieStyle(s string) (SynCookieStyle, error) {
	switch SynCookieStyle(s) {
	case "", SynCookieStyleOOS:
		return SynCookieStyleOOS, nil
	case SynCookieStyleReset:
		return SynCookieStyleReset, nil
	default:
		return "", fmt.Errorf("invalid scrub-syn-cookie-style %q (want oos|reset)", s)
	}
}

// config_map indices and values, mirroring CONFIG_KEY_SC_* and SC_* in
// protector.bpf.c.
const (
	configKeySCMode   uint32 = 7
	configKeySCSynPPS uint32 = 8
	configKeySCTTL    uint32 = 9
	configKeySCStyle  uint32 = 10

	scModeAuto uint32 = 1
	scModeOn   uint32 = 2

	scStyleOOS   uint32 = 0
	scStyleReset uint32 = 1
)

// SynCookieEventNames is indexed like SC_EV_* in protector.bpf.c.
var SynCookieEventNames = []string{"challenge", "dry_run", "valid", "invalid", "passed", "unsupported", "error", "activated"}

// SynCookieConfig is written to config_map once the program is loaded.
type SynCookieConfig struct {
	Mode  SynCookieMode
	Style SynCookieStyle
	// SynPPS is the node-wide SYN rate per destination that activates
	// challenges in auto mode.
	SynPPS uint32
	TTL    time.Duration
}

func synCookieConfigValues(cfg SynCookieConfig, cpus int) (map[uint32]uint32, error) {
	var mode uint32
	switch cfg.Mode {
	case SynCookiesOff, "":
		return nil, errors.New("SYN cookies are off")
	case SynCookiesAuto:
		mode = scModeAuto
		if cfg.SynPPS == 0 {
			return nil, errors.New("auto mode needs a SYN rate threshold above 0")
		}
	case SynCookiesOn:
		mode = scModeOn
	default:
		return nil, fmt.Errorf("invalid SYN cookie mode %q", cfg.Mode)
	}
	style := scStyleOOS
	switch cfg.Style {
	case SynCookieStyleOOS, "":
	case SynCookieStyleReset:
		style = scStyleReset
	default:
		return nil, fmt.Errorf("invalid SYN cookie style %q", cfg.Style)
	}
	ttl := cfg.TTL / time.Second
	if ttl < 1 || ttl > math.MaxUint32 {
		return nil, fmt.Errorf("SYN cookie TTL must be between 1s and %ds, got %s", uint32(math.MaxUint32), cfg.TTL)
	}
	return map[uint32]uint32{
		configKeySCMode: mode,
		// RSS spreads a random-source flood evenly, so each CPU sees its share.
		configKeySCSynPPS: scrubSlowPathPerCPU(cfg.SynPPS, cpus),
		configKeySCTTL:    uint32(ttl),
		configKeySCStyle:  style,
	}, nil
}

// SetSynCookies configures challenges in a program loaded with SYN cookies
// enabled. The mode is written last, so challenges never start with a
// half-written configuration.
func (m *Maps) SetSynCookies(cfg SynCookieConfig) error {
	if m.ConfigMap == nil {
		return errors.New("config_map not loaded")
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("count CPUs: %w", err)
	}
	values, err := synCookieConfigValues(cfg, cpus)
	if err != nil {
		return err
	}
	for _, key := range []uint32{configKeySCSynPPS, configKeySCTTL, configKeySCStyle, configKeySCMode} {
		if err := m.ConfigMap.Put(key, values[key]); err != nil {
			return fmt.Errorf("write config_map[%d]: %w", key, err)
		}
	}
	return nil
}

// SynCookieStats is syncookie_stats summed over CPUs, [family][event].
type SynCookieStats [2][]uint64

func sumSynCookieStats(perIndex [][]uint64) SynCookieStats {
	var s SynCookieStats
	for f := range s {
		s[f] = make([]uint64, len(SynCookieEventNames))
	}
	for i, perCPU := range perIndex {
		f, ev := i/len(SynCookieEventNames), i%len(SynCookieEventNames)
		if f >= len(s) {
			break
		}
		for _, v := range perCPU {
			s[f][ev] += v
		}
	}
	return s
}

func (m *Maps) ReadSynCookieStats() (SynCookieStats, error) {
	if m.SynCookieStats == nil {
		return SynCookieStats{}, errors.New("syncookie_stats map not loaded")
	}
	perIndex := make([][]uint64, 2*len(SynCookieEventNames))
	for i := range perIndex {
		if err := m.SynCookieStats.Lookup(uint32(i), &perIndex[i]); err != nil {
			return SynCookieStats{}, fmt.Errorf("read syncookie_stats[%d]: %w", i, err)
		}
	}
	return sumSynCookieStats(perIndex), nil
}

// CountVerifiedSources counts sources verified less than ttl ago. nowNS is
// CLOCK_MONOTONIC, the clock of bpf_ktime_get_ns; the LRU maps also hold
// expired entries until they are evicted.
func (m *Maps) CountVerifiedSources(w *MapWalker, nowNS uint64, ttl time.Duration) (v4, v6 int, err error) {
	if m.SynCookieVerifiedV4 == nil || m.SynCookieVerifiedV6 == nil {
		return 0, 0, errors.New("syncookie_verified maps not loaded")
	}
	ttlNS := uint64(ttl.Truncate(time.Second))
	if err := Walk(w, m.SynCookieVerifiedV4, func(_ [4]byte, t uint64) bool {
		if nowNS-t < ttlNS {
			v4++
		}
		return true
	}); err != nil {
		return 0, 0, fmt.Errorf("walk syncookie_verified_v4: %w", err)
	}
	if err := Walk(w, m.SynCookieVerifiedV6, func(_ [16]byte, t uint64) bool {
		if nowNS-t < ttlNS {
			v6++
		}
		return true
	}); err != nil {
		return 0, 0, fmt.Errorf("walk syncookie_verified_v6: %w", err)
	}
	return v4, v6, nil
}
