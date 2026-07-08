package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestCheckKernelSynCookiesMissingFile ensures the check tolerates a missing
// sysctl file (e.g. non-Linux dev machines, unprivileged sandboxes) without
// panicking or requiring a logger.
func TestCheckKernelSynCookiesMissingFile(t *testing.T) {
	c := &Collector{Logger: logrus.New()}
	c.checkKernelSynCookiesAtPath(filepath.Join(t.TempDir(), "does-not-exist"))

	// Also verify nil-logger safety.
	c2 := &Collector{}
	c2.checkKernelSynCookiesAtPath(filepath.Join(t.TempDir(), "does-not-exist"))
}

// TestCheckKernelSynCookiesDisabled and Enabled exercise the two real
// sysctl values without needing root or a Linux host, by pointing the
// checker at a fixture file.
func TestCheckKernelSynCookiesDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp_syncookies")
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	c := &Collector{Logger: logrus.New()}
	c.checkKernelSynCookiesAtPath(path) // Should log a Warn; no panic/error return to assert on.
}

func TestCheckKernelSynCookiesEnabled(t *testing.T) {
	for _, val := range []string{"1", "2"} {
		path := filepath.Join(t.TempDir(), "tcp_syncookies")
		if err := os.WriteFile(path, []byte(val+"\n"), 0o644); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		c := &Collector{Logger: logrus.New()}
		c.checkKernelSynCookiesAtPath(path) // Should log Info; no panic/error return to assert on.
	}
}
