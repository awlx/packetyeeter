package ebpf

// configKeyMonitorMode is the config_map array index checked by the XDP
// program (as `key_monitor = 1` in protector.bpf.c) before every enforcement
// drop (bad flags, SYN-flood blocklist, ICMP/UDP rate limits, allowlist).
const configKeyMonitorMode uint32 = 1

// configKeyEgressAccounting is the config_map array index checked by the TC
// egress program (as CONFIG_KEY_EGRESS_ACCOUNTING in protector.bpf.c) before
// adding a packet's length to the per-client egress byte counter. It defaults
// to 0 so the accounting is inert until an operator enables it.
const configKeyEgressAccounting uint32 = 3

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
