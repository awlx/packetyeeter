//go:build !linux

package ebpf

import (
	"fmt"
	"runtime"
)

type LoaderConfig struct {
	Mode         Mode
	Interface    string
	InsideIface  string
	XDPMode      XDPMode
	AllowGeneric bool
	Fingerprints bool
	SynCookies   bool
	HandshakeLRU HandshakeLRU
}

type Loader struct {
	iface string
	maps  *Maps
}

func NewLoader(cfg LoaderConfig) *Loader {
	return &Loader{
		iface: cfg.Interface,
	}
}

func (l *Loader) HandshakeSizing() HandshakeSizing { return HandshakeSizing{} }

func (l *Loader) ScrubAttached() error {
	return fmt.Errorf("eBPF collector is only supported on Linux, not %s", runtime.GOOS)
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
