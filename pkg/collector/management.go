package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"PacketYeeter/pkg/collector/ebpf"
)

const managementReadTimeout = 5 * time.Second

type aiSummary struct {
	DetectionsByIP   map[string]int `json:"detections_by_ip"`
	DetectionsByJA4H map[string]int `json:"detections_by_ja4h"`
	DetectionsByASN  map[string]int `json:"detections_by_asn"`
}

type botStats struct {
	TotalDetections    int            `json:"total_detections"`
	ByCategory         map[string]int `json:"by_category"`
	ByVerification     map[string]int `json:"by_verification"`
	BehavioralPatterns map[string]int `json:"behavioral_patterns"`
}

func (c *Collector) startManagementSocket() error {
	if err := prepareUnixSocket(c.Config.SocketPath); err != nil {
		return err
	}

	// Refuse to create the socket in a directory another local user could use
	// to swap the socket path for a symlink between our checks and the bind
	// (TOCTOU). A world-writable directory without the sticky bit is the
	// dangerous case; a group-writable one is only a warning.
	if err := checkSocketParentDir(c.Config.SocketPath); err != nil {
		return err
	}
	if warn := socketParentDirGroupWritable(c.Config.SocketPath); warn != "" {
		c.Logger.WithField("socket", c.Config.SocketPath).Warn(warn)
	}

	// Bind with a tightened umask so the socket is created 0600 atomically.
	// net.Listen otherwise creates it 0777&^umask, leaving a window before the
	// os.Chmod below where another local user could connect and read the
	// blocked-IP set. The chmod is kept as belt-and-suspenders.
	listener, err := listenUnixOwnerOnly(c.Config.SocketPath)
	if err != nil {
		return err
	}
	// The socket is created with 0777&^umask, so a permissive umask leaves
	// it group/world-connectable. Commands are read-only today but disclose
	// the blocked-IP set; restrict to the owning user (typically root, same
	// as yeetctl runs).
	if err := os.Chmod(c.Config.SocketPath, 0o600); err != nil {
		listener.Close()
		return fmt.Errorf("failed to restrict management socket permissions: %w", err)
	}
	c.managementListener = listener

	c.wg.Add(1)
	go c.serveManagementSocket(listener)

	c.Logger.WithField("socket", c.Config.SocketPath).Info("Started management socket")
	return nil
}

// listenUnixOwnerOnly binds a unix-domain listener whose socket file is created
// owner-only (0600) from the outset, by tightening the process umask across the
// bind. umask is process-global, so this is called only at startup where no
// other goroutine is creating files; the window is a few syscalls wide.
func listenUnixOwnerOnly(path string) (net.Listener, error) {
	old := syscall.Umask(0o177) // 0777 &^ 0177 = 0600
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}

// checkSocketParentDir rejects a socket whose parent directory is writable by
// other local users without the sticky bit set, which would let them
// rename/replace the socket path (a symlink-swap TOCTOU). World-writable
// non-sticky directories are refused outright.
func checkSocketParentDir(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot stat management socket directory %s: %w", dir, err)
	}
	mode := info.Mode()
	if mode.Perm()&0o002 != 0 && mode&os.ModeSticky == 0 {
		return fmt.Errorf("management socket directory %s is world-writable without the sticky bit (mode %#o); refusing to create a socket there to avoid symlink-swap attacks", dir, mode.Perm())
	}
	return nil
}

// socketParentDirGroupWritable returns a warning string if the socket's parent
// directory is group-writable without the sticky bit (a lesser risk than
// world-writable but still worth surfacing), or "" if it is safe.
func socketParentDirGroupWritable(path string) string {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return ""
	}
	mode := info.Mode()
	if mode.Perm()&0o020 != 0 && mode&os.ModeSticky == 0 {
		return fmt.Sprintf("management socket directory %s is group-writable without the sticky bit (mode %#o); ensure the group is trusted", dir, mode.Perm())
	}
	return ""
}

func (c *Collector) stopManagementSocket() {
	if c.managementListener != nil {
		if err := c.managementListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.Logger.WithError(err).Warn("Management socket close error")
		}
		c.managementListener = nil
	}
	if c.Config.SocketPath != "" {
		if err := os.Remove(c.Config.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.Logger.WithError(err).WithField("socket", c.Config.SocketPath).Warn("Failed to remove management socket")
		}
	}
}

func (c *Collector) serveManagementSocket(listener net.Listener) {
	defer c.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || (c.ctx != nil && c.ctx.Err() != nil) {
				return
			}
			c.Logger.WithError(err).Warn("Management socket accept error")
			continue
		}

		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.handleManagementConnection(conn)
		}()
	}
}

func (c *Collector) handleManagementConnection(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(managementReadTimeout)); err != nil {
		c.Logger.WithError(err).Debug("Failed to set management socket read deadline")
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		c.Logger.WithError(err).Debug("Failed to read management command")
		return
	}

	command := strings.ToUpper(strings.TrimSpace(string(buf[:n])))
	if err := json.NewEncoder(conn).Encode(c.managementResponse(command)); err != nil {
		c.Logger.WithError(err).Debug("Failed to write management response")
	}
}

func (c *Collector) managementResponse(command string) any {
	switch command {
	case "LIST":
		list := ebpf.BlockedIPList{
			IPv4:        []ebpf.BlockedIPInfo{},
			IPv6:        []ebpf.BlockedIPInfo{},
			MonitorMode: false,
		}
		if c.Maps != nil {
			if c.Maps.BlockedIPs != nil && c.Maps.BlockedIPsV6 != nil {
				list.IPv4, list.IPv6 = c.Maps.ListBlockedIPs(c.Config.BlockDuration)
			}
			list.MonitorMode = c.Maps.DryRun
		}
		return list
	case "REPUTATION":
		return map[string]any{}
	case "AI":
		return aiSummary{
			DetectionsByIP:   map[string]int{},
			DetectionsByJA4H: map[string]int{},
			DetectionsByASN:  map[string]int{},
		}
	case "BOTS":
		return botStats{
			ByCategory:         map[string]int{},
			ByVerification:     map[string]int{},
			BehavioralPatterns: map[string]int{},
		}
	default:
		return map[string]string{"error": fmt.Sprintf("unknown command %q", command)}
	}
}

func prepareUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a unix socket", path)
	}

	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		return fmt.Errorf("%s is already in use", path)
	}
	return os.Remove(path)
}
