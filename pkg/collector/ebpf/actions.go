package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func (m *Maps) BlockIP(ip net.IP, reason string, meta logrus.Fields) error {
	// AllowList: Never block loopback, private networks (RFC1918), or link-local
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}

	// Dynamic AllowList (User Configured)
	for _, subnet := range m.AllowedNets {
		if subnet.Contains(ip) {
			// Ensure we don't log spam if they are being noisy but allowed
			// Or should we log "Allowed but bad"? For now, just silently allow.
			return nil
		}
	}

	// Prepare log fields
	if meta == nil {
		meta = logrus.Fields{}
	}
	meta["ip"] = ip.String()

	// Only set "reason" if not provided in meta
	if _, ok := meta["reason"]; !ok {
		meta["reason"] = reason
	}

	if m.DryRun {
		meta["action"] = "WOULD BLOCK (Monitor Mode)"
		meta["level"] = "warning"
		// Ensure consistency with poller logs
		if _, ok := meta["proto"]; !ok {
			meta["proto"] = "TCP" // Default assumption if not provided
		}

		logrus.WithFields(meta).Warn(reason)
		// Fallthrough to write to map so XDP can count "would be blocked" packets
		// XDP will NOT drop because of the global monitor_mode flag.
	} else {
		meta["action"] = "Blocked temporarily"
		logrus.WithFields(meta).Warn(reason)
	}

	now := getKTimeNs()

	if ip4 := ip.To4(); ip4 != nil {
		key := binary.LittleEndian.Uint32(ip4)
		if err := m.BlockedIPs.Put(key, now); err != nil {
			return fmt.Errorf("failed to block IPv4: %w", err)
		}
	} else {
		var key [16]byte
		copy(key[:], ip.To16())
		if err := m.BlockedIPsV6.Put(key, now); err != nil {
			return fmt.Errorf("failed to block IPv6: %w", err)
		}
	}

	meta["action"] = "Blocked temporarily"
	logrus.WithFields(meta).Warn(reason)
	return nil
}

func (m *Maps) UnblockIP(ip net.IP) error {
	if ip4 := ip.To4(); ip4 != nil {
		key := binary.LittleEndian.Uint32(ip4)
		return m.BlockedIPs.Delete(key)
	} else {
		var key [16]byte
		copy(key[:], ip.To16())
		return m.BlockedIPsV6.Delete(key)
	}
}

func getKTimeNs() uint64 {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return 0
	}
	return uint64(ts.Nano())
}

type BlockedIPInfo struct {
	IP           string `json:"ip"`
	RemainingTTL string `json:"remaining_ttl"`
}

type BlockedIPList struct {
	IPv4        []BlockedIPInfo `json:"ipv4"`
	IPv6        []BlockedIPInfo `json:"ipv6"`
	MonitorMode bool            `json:"monitor_mode"`
}

func (m *Maps) ListBlockedIPs(blockDuration time.Duration) ([]BlockedIPInfo, []BlockedIPInfo) {
	var v4 []BlockedIPInfo
	var v6 []BlockedIPInfo

	now := getKTimeNs()
	blockDurationNs := uint64(blockDuration.Nanoseconds())

	// Iterate IPv4
	var key4 uint32
	var valFn uint64
	iter4 := m.BlockedIPs.Iterate()
	for iter4.Next(&key4, &valFn) {
		elapsed := now - valFn
		var ttl string
		if elapsed < blockDurationNs {
			remaining := time.Duration(blockDurationNs-elapsed) * time.Nanosecond
			ttl = remaining.Round(time.Second).String()
		} else {
			ttl = "expired"
		}

		bytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(bytes, key4)

		v4 = append(v4, BlockedIPInfo{
			IP:           net.IP(bytes).String(),
			RemainingTTL: ttl,
		})
	}

	// Iterate IPv6
	var key6 [16]byte
	iter6 := m.BlockedIPsV6.Iterate()
	for iter6.Next(&key6, &valFn) {
		elapsed := now - valFn
		var ttl string
		if elapsed < blockDurationNs {
			remaining := time.Duration(blockDurationNs-elapsed) * time.Nanosecond
			ttl = remaining.Round(time.Second).String()
		} else {
			ttl = "expired"
		}

		v6 = append(v6, BlockedIPInfo{
			IP:           net.IP(key6[:]).String(),
			RemainingTTL: ttl,
		})
	}

	return v4, v6
}
