//go:build !linux

package ebpf

import (
	"fmt"
	"runtime"
)

type Loader struct {
	iface string
	maps  *Maps
}

func NewLoader(iface string) *Loader {
	return &Loader{
		iface: iface,
	}
}

func (l *Loader) Load() error {
	return fmt.Errorf("eBPF collector is only supported on Linux, not %s", runtime.GOOS)
}

func (l *Loader) Attach() error {
	return fmt.Errorf("eBPF collector is only supported on Linux, not %s", runtime.GOOS)
}

func (l *Loader) Close() {}

func (l *Loader) GetMaps() *Maps {
	return l.maps
}
