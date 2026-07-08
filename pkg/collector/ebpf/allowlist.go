package ebpf

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// lpmKeyV4 mirrors `struct lpm_key_v4` in protector.bpf.c: a big-endian
// (network byte order) IPv4 address keyed by prefix length for the
// allowlist_v4 LPM trie map.
type lpmKeyV4 struct {
	Prefixlen uint32
	Data      [4]byte
}

// lpmKeyV6 mirrors `struct lpm_key_v6` in protector.bpf.c for the
// allowlist_v6 LPM trie map.
type lpmKeyV6 struct {
	Prefixlen uint32
	Data      [16]byte
}

// allowlistValue is a placeholder value for the allowlist LPM trie maps;
// only key existence is checked in eBPF, so the value content is unused.
type allowlistValue = uint64

// lpmKeyFromNet builds the LPM trie key for ipNet, returning either a v4 or
// v6 key depending on the network's address family.
func lpmKeyFromNet(ipNet *net.IPNet) (v4 *lpmKeyV4, v6 *lpmKeyV6, err error) {
	if ipNet == nil {
		return nil, nil, fmt.Errorf("nil network")
	}

	ones, bits := ipNet.Mask.Size()
	switch bits {
	case 32:
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			return nil, nil, fmt.Errorf("invalid IPv4 address %q", ipNet.IP)
		}
		key := &lpmKeyV4{Prefixlen: uint32(ones)}
		copy(key.Data[:], ip4)
		return key, nil, nil
	case 128:
		ip6 := ipNet.IP.To16()
		if ip6 == nil {
			return nil, nil, fmt.Errorf("invalid IPv6 address %q", ipNet.IP)
		}
		key := &lpmKeyV6{Prefixlen: uint32(ones)}
		copy(key.Data[:], ip6)
		return nil, key, nil
	default:
		return nil, nil, fmt.Errorf("unsupported mask size %d for %q", bits, ipNet.IP)
	}
}

// AddAllowlistEntry inserts a CIDR into the kernel-space allowlist maps so
// XDP/TC can bypass matching traffic directly, instead of relying solely on
// the slower userspace block-decision path.
func (m *Maps) AddAllowlistEntry(ipNet *net.IPNet) error {
	v4, v6, err := lpmKeyFromNet(ipNet)
	if err != nil {
		return err
	}

	if v4 != nil {
		if m.AllowListV4 == nil {
			return nil
		}
		if err := m.AllowListV4.Put(v4, allowlistValue(1)); err != nil {
			return fmt.Errorf("failed to add %s to kernel IPv4 allowlist: %w", ipNet, err)
		}
		return nil
	}

	if m.AllowListV6 == nil {
		return nil
	}
	if err := m.AllowListV6.Put(v6, allowlistValue(1)); err != nil {
		return fmt.Errorf("failed to add %s to kernel IPv6 allowlist: %w", ipNet, err)
	}
	return nil
}

// RemoveAllowlistEntry deletes a previously added CIDR from the kernel-space
// allowlist maps. It is not an error for the entry to already be absent.
func (m *Maps) RemoveAllowlistEntry(ipNet *net.IPNet) error {
	v4, v6, err := lpmKeyFromNet(ipNet)
	if err != nil {
		return err
	}

	if v4 != nil {
		if m.AllowListV4 == nil {
			return nil
		}
		if err := m.AllowListV4.Delete(v4); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to remove %s from kernel IPv4 allowlist: %w", ipNet, err)
		}
		return nil
	}

	if m.AllowListV6 == nil {
		return nil
	}
	if err := m.AllowListV6.Delete(v6); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("failed to remove %s from kernel IPv6 allowlist: %w", ipNet, err)
	}
	return nil
}

// SyncAllowlist populates the kernel-space allowlist maps from nets. It is
// intended for one-time startup population from the configured -allowlist
// flag; entries added dynamically afterwards (e.g. by analyzer commands)
// should use AddAllowlistEntry/RemoveAllowlistEntry instead.
func (m *Maps) SyncAllowlist(nets []*net.IPNet) error {
	var firstErr error
	for _, n := range nets {
		if err := m.AddAllowlistEntry(n); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
