package collector

import (
	"os"
	"strings"
)

// synCookiesSysctlPath is the standard Linux sysctl file controlling the
// kernel's own SYN cookie protection. PacketYeeter deliberately does not
// implement its own SYN cookie challenge/response in XDP: doing so
// transparently is not achievable without breaking the TCP protocol (the
// client would end up receiving a second, unexpected SYN-ACK once its
// "established" connection was hypothetically handed off to the real
// kernel stack). Instead, PacketYeeter's incomplete-handshake detection
// and blocked_ips enforcement reduce the SYN flood volume that reaches
// the backend at all, and operators are expected to rely on the kernel's
// own syncookie implementation for the rest.
const synCookiesSysctlPath = "/proc/sys/net/ipv4/tcp_syncookies"

// checkKernelSynCookies reads the kernel's tcp_syncookies sysctl and logs a
// warning if it looks disabled (value "0"). It is a no-op (debug-only log)
// if the file cannot be read, e.g. on non-Linux development machines or in
// unprivileged/sandboxed test environments.
func (c *Collector) checkKernelSynCookies() {
	c.checkKernelSynCookiesAtPath(synCookiesSysctlPath)
}

// checkKernelSynCookiesAtPath is the testable core of checkKernelSynCookies,
// parameterized on the sysctl path so tests can point it at a fixture file
// instead of requiring root/Linux to exercise the disabled/enabled branches.
func (c *Collector) checkKernelSynCookiesAtPath(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if c.Logger != nil {
			c.Logger.WithError(err).Debug("Could not read tcp_syncookies sysctl; skipping SYN flood mitigation check")
		}
		return
	}

	value := strings.TrimSpace(string(data))
	if c.Logger == nil {
		return
	}

	if value == "0" {
		c.Logger.Warn("net.ipv4.tcp_syncookies is disabled (0). PacketYeeter relies on the kernel's own SYN cookie " +
			"protection to survive SYN floods once its own incomplete-handshake blocking is saturated; enable it " +
			"with 'sysctl -w net.ipv4.tcp_syncookies=1' (and persist via /etc/sysctl.conf).")
		return
	}

	c.Logger.WithField("tcp_syncookies", value).Info("Kernel SYN cookie protection is enabled")
}
