package collector

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"PacketYeeter/pkg/collector/ebpf"

	"github.com/sirupsen/logrus"
)

func newTestCollector(t *testing.T, socketPath string) *Collector {
	t.Helper()

	logger := logrus.New()
	logger.SetOutput(os.Stderr)

	c := &Collector{
		Config: Config{
			SocketPath:    socketPath,
			BlockDuration: 5 * time.Minute,
		},
		Logger: logger,
		Maps: &ebpf.Maps{
			DryRun: true,
		},
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	return c
}

func TestManagementSocketCommands(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "collector.sock")
	c := newTestCollector(t, socketPath)

	if err := c.startManagementSocket(); err != nil {
		t.Fatalf("start management socket: %v", err)
	}
	t.Cleanup(func() {
		c.cancel()
		c.stopManagementSocket()
		c.wg.Wait()
	})

	t.Run("LIST", func(t *testing.T) {
		var response ebpf.BlockedIPList
		sendManagementCommand(t, socketPath, "LIST", &response)

		if !response.MonitorMode {
			t.Fatalf("expected monitor mode to reflect maps dry-run state")
		}
		if len(response.IPv4) != 0 || len(response.IPv6) != 0 {
			t.Fatalf("expected empty blocked lists, got IPv4=%d IPv6=%d", len(response.IPv4), len(response.IPv6))
		}
	})

	t.Run("REPUTATION", func(t *testing.T) {
		var response map[string]any
		sendManagementCommand(t, socketPath, "REPUTATION", &response)

		if len(response) != 0 {
			t.Fatalf("expected empty reputation table, got %#v", response)
		}
	})

	t.Run("AI", func(t *testing.T) {
		var response aiSummary
		sendManagementCommand(t, socketPath, "AI", &response)

		if len(response.DetectionsByIP) != 0 || len(response.DetectionsByJA4H) != 0 || len(response.DetectionsByASN) != 0 {
			t.Fatalf("expected empty AI summary, got %#v", response)
		}
	})

	t.Run("BOTS", func(t *testing.T) {
		var response botStats
		sendManagementCommand(t, socketPath, "BOTS", &response)

		if response.TotalDetections != 0 || len(response.ByCategory) != 0 || len(response.ByVerification) != 0 || len(response.BehavioralPatterns) != 0 {
			t.Fatalf("expected empty bot stats, got %#v", response)
		}
	})
}

func TestPrepareUnixSocket(t *testing.T) {
	t.Run("removes stale socket", func(t *testing.T) {
		socketPath := filepath.Join(shortTempDir(t), "stale.sock")
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("create unix socket: %v", err)
		}
		if err := listener.Close(); err != nil {
			t.Fatalf("close unix socket: %v", err)
		}

		if err := prepareUnixSocket(socketPath); err != nil {
			t.Fatalf("prepare stale socket: %v", err)
		}
		if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
			t.Fatalf("expected stale socket to be removed, got err=%v", err)
		}
	})

	t.Run("rejects non-socket path", func(t *testing.T) {
		socketPath := filepath.Join(shortTempDir(t), "not-a-socket")
		if err := os.WriteFile(socketPath, []byte("nope"), 0o600); err != nil {
			t.Fatalf("write test file: %v", err)
		}

		if err := prepareUnixSocket(socketPath); err == nil {
			t.Fatalf("expected non-socket path to be rejected")
		}
	})
}

// The management socket discloses the blocked-IP set and must be owner-only.
// Creating it must be atomic (0600 from the outset via umask), not left briefly
// group/world-connectable before a chmod.
func TestManagementSocketCreatedOwnerOnly(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "collector.sock")
	c := newTestCollector(t, socketPath)

	if err := c.startManagementSocket(); err != nil {
		t.Fatalf("start management socket: %v", err)
	}
	t.Cleanup(func() {
		c.cancel()
		c.stopManagementSocket()
		c.wg.Wait()
	})

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("management socket mode = %#o, want 0600 (owner-only)", perm)
	}
}

// A world-writable parent directory without the sticky bit invites a
// symlink-swap TOCTOU, so socket creation must refuse it.
func TestManagementSocketRejectsWorldWritableParentDir(t *testing.T) {
	dir := shortTempDir(t)
	if err := os.Chmod(dir, 0o777); err != nil { // world-writable, no sticky
		t.Fatalf("chmod dir: %v", err)
	}
	if err := checkSocketParentDir(filepath.Join(dir, "collector.sock")); err == nil {
		t.Fatal("expected a world-writable non-sticky parent directory to be rejected")
	}

	// A sticky world-writable dir (like /tmp) is safe from cross-user renames.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod sticky: %v", err)
	}
	if err := checkSocketParentDir(filepath.Join(dir, "collector.sock")); err != nil {
		t.Fatalf("sticky world-writable dir should be accepted, got %v", err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "pyt-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("remove temp dir: %v", err)
		}
	})
	return dir
}

func sendManagementCommand(t *testing.T, socketPath, command string, response any) {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial management socket: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(command)); err != nil {
		t.Fatalf("write command: %v", err)
	}
	if err := json.NewDecoder(conn).Decode(response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
