package ebpf

import "fmt"

// configKeyMonitorMode is the config_map array index checked by the XDP
// program (as `key_monitor = 1` in protector.bpf.c) before every enforcement
// drop (bad flags, SYN-flood blocklist, ICMP/UDP rate limits, allowlist).
const configKeyMonitorMode uint32 = 1

// configKeyEgressAccounting is the config_map array index checked by the TC
// egress program (as CONFIG_KEY_EGRESS_ACCOUNTING in protector.bpf.c) before
// adding a packet's length to the per-client egress byte counter. It defaults
// to 0 so the accounting is inert until an operator enables it.
const configKeyEgressAccounting uint32 = 3

// configKeyUDPFragMode is the config_map array index for fragmented UDP /
// IPv6 fragment handling (CONFIG_KEY_UDP_FRAG_MODE in protector.bpf.c).
const configKeyUDPFragMode uint32 = 4

// UDP fragment policy modes written to config_map[configKeyUDPFragMode].
const (
	// UDPFragModeRate is the default: do not hard-drop solely for
	// fragmentation; apply the normal UDP rate limit instead.
	UDPFragModeRate uint32 = 0
	// UDPFragModeDrop is the legacy unconditional drop of fragmented UDP
	// (IPv4) and IPv6 Fragment extension headers.
	UDPFragModeDrop uint32 = 1
)

// ParseUDPFragMode accepts operator-facing mode names.
func ParseUDPFragMode(s string) (uint32, error) {
	switch s {
	case "", "rate":
		return UDPFragModeRate, nil
	case "drop":
		return UDPFragModeDrop, nil
	default:
		return 0, fmt.Errorf("invalid udp-frag-mode %q (want rate|drop)", s)
	}
}

// SetEgressAccounting toggles per-client egress byte accounting in the TC
// egress program. When disabled the program still performs one array lookup
// per egress packet but touches neither egress byte map, so the per-client
// LRU maps stay empty and cost nothing.
//
// It is a safe no-op (not an error) when ConfigMap is nil, e.g. on unsupported
// platforms or before the collector has finished loading eBPF.
func (m *Maps) SetEgressAccounting(enabled bool) error {
	if m.ConfigMap == nil {
		return nil
	}

	var value uint32
	if enabled {
		value = 1
	}

	return m.ConfigMap.Put(configKeyEgressAccounting, value)
}

// SetUDPFragMode configures fragmented UDP / IPv6 fragment handling.
// See UDPFragModeRate and UDPFragModeDrop. No-op when ConfigMap is nil.
func (m *Maps) SetUDPFragMode(mode uint32) error {
	if mode != UDPFragModeRate && mode != UDPFragModeDrop {
		return fmt.Errorf("invalid udp frag mode %d", mode)
	}
	if m.ConfigMap == nil {
		return nil
	}
	return m.ConfigMap.Put(configKeyUDPFragMode, mode)
}

// SetMonitorMode toggles the collector's kernel-space dry-run/monitor mode.
// When enabled is true, the XDP program's `is_monitor` check causes every
// enforcement path to log/count matching traffic without ever returning
// XDP_DROP. This is independent of the analyzer's own -dry-run flag, which
// only suppresses BLOCK commands sent back to the collector over gRPC - it
// has no effect on the collector's own kernel-level detections.
//
// It is a safe no-op (not an error) when ConfigMap is nil, e.g. on
// unsupported platforms or before the collector has finished loading eBPF.
func (m *Maps) SetMonitorMode(enabled bool) error {
	m.DryRun = enabled

	if m.ConfigMap == nil {
		return nil
	}

	var value uint32
	if enabled {
		value = 1
	}

	return m.ConfigMap.Put(configKeyMonitorMode, value)
}
