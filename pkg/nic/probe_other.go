//go:build !linux

package nic

import (
	"fmt"
	"runtime"
)

func Probe(iface string) (*Info, error) {
	return nil, fmt.Errorf("NIC checks need Linux, not %s", runtime.GOOS)
}
