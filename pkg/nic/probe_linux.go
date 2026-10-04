//go:build linux

package nic

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Probe gathers everything Check needs about iface without changing anything:
// sysfs, procfs, ethtool ioctls/CLI and netlink reads only.
func Probe(iface string) (*Info, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	info := &Info{Name: iface, Ifindex: ifi.Index, MTU: ifi.MTU, CPUs: runtime.NumCPU(), NUMANode: -1, SpeedMbps: -1}
	var uts unix.Utsname
	if unix.Uname(&uts) == nil {
		info.Kernel = unix.ByteSliceToString(uts.Release[:])
	}

	sys := filepath.Join("/sys/class/net", iface)
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0); err == nil {
		if d, err := unix.IoctlGetEthtoolDrvinfo(fd, iface); err == nil {
			info.Driver = unix.ByteSliceToString(d.Driver[:])
			info.DriverVersion = unix.ByteSliceToString(d.Version[:])
			info.Firmware = unix.ByteSliceToString(d.Fw_version[:])
			info.BusInfo = unix.ByteSliceToString(d.Bus_info[:])
		}
		unix.Close(fd)
	}
	if info.Driver == "" {
		if l, err := os.Readlink(filepath.Join(sys, "device/driver")); err == nil {
			info.Driver = filepath.Base(l)
		}
	}
	if v, ok := readInt(filepath.Join(sys, "speed")); ok {
		info.SpeedMbps = v
	}
	if v, ok := readInt(filepath.Join(sys, "device/numa_node")); ok {
		info.NUMANode = v
	}
	if info.NUMANode >= 0 {
		info.NUMACPUs = readCPUList(fmt.Sprintf("/sys/devices/system/node/node%d/cpulist", info.NUMANode))
	}
	info.RxQueues, info.TxQueues = countQueues(filepath.Join(sys, "queues"))
	info.IRQCPUs, info.IRQs = irqAffinity(filepath.Join(sys, "device/msi_irqs"))
	info.IRQBalance = processRunning("irqbalance")
	if v, ok := readInt(filepath.Join(sys, "napi_defer_hard_irqs")); ok {
		info.NAPIDeferHardIRQs = v
	}
	if v, ok := readInt(filepath.Join(sys, "gro_flush_timeout")); ok {
		info.GROFlushTimeout = v
	}
	if v, ok := readInt(filepath.Join(sys, "threaded")); ok {
		info.ThreadedNAPI = v == 1
	}
	if v, ok := readInt("/proc/sys/net/core/busy_poll"); ok {
		info.BusyPoll = v
	}

	info.XDPMode, info.XDPProgID, err = XDPAttachMode(ifi.Index)
	if err != nil {
		info.Errors = append(info.Errors, fmt.Sprintf("xdp attach state: %v", err))
	}
	if info.XDPProgID != 0 {
		if p, err := ebpf.NewProgramFromID(ebpf.ProgramID(info.XDPProgID)); err == nil {
			if pi, err := p.Info(); err == nil {
				info.XDPProgName = pi.Name
			}
			p.Close()
		}
	}
	f, err := QueryDevFeatures(ifi.Index)
	switch {
	case err == nil:
		info.Features = &f
	case errors.Is(err, ErrNoNetdevFamily):
		info.Errors = append(info.Errors, err.Error())
	default:
		info.Errors = append(info.Errors, fmt.Sprintf("xdp features: %v", err))
	}

	if _, err := exec.LookPath("ethtool"); err != nil {
		info.Errors = append(info.Errors, "ethtool not found: ring sizes, channels and offloads not checked")
		return info, nil
	}
	if out, err := exec.Command("ethtool", "-g", iface).Output(); err == nil {
		info.Rings = parseEthtoolRings(string(out))
	}
	if out, err := exec.Command("ethtool", "-l", iface).Output(); err == nil {
		info.Channels = parseEthtoolChannels(string(out))
	}
	if out, err := exec.Command("ethtool", "-k", iface).Output(); err == nil {
		info.Offloads = parseEthtoolFeatures(string(out))
	}
	return info, nil
}

func readInt(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return v, err == nil
}

func readCPUList(path string) []int {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseCPUList(strings.TrimSpace(string(b)))
}

func countQueues(dir string) (rx, tx int) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), "rx-"):
			rx++
		case strings.HasPrefix(e.Name(), "tx-"):
			tx++
		}
	}
	return rx, tx
}

// irqAffinity returns the distinct CPUs the device's MSI vectors may fire on,
// and the number of vectors.
func irqAffinity(dir string) ([]int, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}
	seen := map[int]bool{}
	for _, e := range entries {
		for _, c := range readCPUList(filepath.Join("/proc/irq", e.Name(), "smp_affinity_list")) {
			seen[c] = true
		}
	}
	cpus := make([]int, 0, len(seen))
	for c := range seen {
		cpus = append(cpus, c)
	}
	sort.Ints(cpus)
	return cpus, len(entries)
}

func processRunning(comm string) bool {
	dirs, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, d := range dirs {
		if b, err := os.ReadFile(d); err == nil && strings.TrimSpace(string(b)) == comm {
			return true
		}
	}
	return false
}
