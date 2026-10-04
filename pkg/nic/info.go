package nic

import (
	"bufio"
	"strconv"
	"strings"
)

// Info is a read-only snapshot of one interface.
type Info struct {
	Name          string
	Ifindex       int
	Kernel        string
	Driver        string
	DriverVersion string
	Firmware      string
	BusInfo       string
	SpeedMbps     int // -1 when unknown (virtual devices, link down)
	MTU           int
	NUMANode      int // -1 when unknown or not NUMA
	NUMACPUs      []int
	CPUs          int
	RxQueues      int
	TxQueues      int
	IRQs          int
	IRQCPUs       []int
	IRQBalance    bool

	NAPIDeferHardIRQs int
	GROFlushTimeout   int
	ThreadedNAPI      bool
	BusyPoll          int

	XDPMode     uint32
	XDPProgID   uint32
	XDPProgName string
	Features    *DevFeatures // nil when the kernel cannot report them

	Rings    *MaxCur // RX ring descriptors
	Channels *MaxCur // combined channels
	Offloads map[string]Offload

	Errors []string
}

// MaxCur is an ethtool "pre-set maximum" and "current" pair; -1 means n/a.
type MaxCur struct {
	Max, Cur int
}

type Offload struct {
	On    bool
	Fixed bool
}

// parseEthtoolPairs reads ethtool -g/-l output and returns the named field's
// maximum and current values.
func parseEthtoolPairs(out, field string) *MaxCur {
	res := &MaxCur{Max: -1, Cur: -1}
	section := ""
	found := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Pre-set maximums"):
			section = "max"
			continue
		case strings.HasPrefix(line, "Current hardware settings"):
			section = "cur"
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(k) != field {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			continue
		}
		found = true
		if section == "max" {
			res.Max = n
		} else if section == "cur" {
			res.Cur = n
		}
	}
	if !found {
		return nil
	}
	return res
}

func parseEthtoolRings(out string) *MaxCur { return parseEthtoolPairs(out, "RX") }

// parseEthtoolChannels prefers combined channels, which almost every
// multi-queue driver uses; separate RX channels are the fallback.
func parseEthtoolChannels(out string) *MaxCur {
	if c := parseEthtoolPairs(out, "Combined"); c != nil && c.Cur > 0 {
		return c
	}
	return parseEthtoolPairs(out, "RX")
}

func parseEthtoolFeatures(out string) map[string]Offload {
	res := map[string]Offload{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if !strings.HasPrefix(v, "on") && !strings.HasPrefix(v, "off") {
			continue
		}
		res[k] = Offload{On: strings.HasPrefix(v, "on"), Fixed: strings.Contains(v, "[fixed]")}
	}
	return res
}

// parseCPUList parses the kernel's cpulist format ("0-3,8,10-11").
func parseCPUList(s string) []int {
	var cpus []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		for c := a; c <= b; c++ {
			cpus = append(cpus, c)
		}
	}
	return cpus
}
