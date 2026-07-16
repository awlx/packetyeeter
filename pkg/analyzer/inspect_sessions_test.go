package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

// Recordings are persisted as recording-*.jsonl; the delete endpoint used to
// glob sessions_*.jsonl and could therefore never find one.
func TestDeleteSessionFromDiskRemovesRecording(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "recording-192.0.2.9-2026-07-16T10-00-00.jsonl")
	line := `{"SessionID":"192.0.2.9_1752660000"}` + "\n"
	if err := os.WriteFile(file, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := deleteSessionFromDisk(dir, "192.0.2.9_1752660000"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("recording file should be removed when its only session is deleted")
	}

	sessions, err := loadSessionsFromDisk(dir)
	if err != nil || len(sessions) != 0 {
		t.Fatalf("loadSessionsFromDisk = (%d sessions, %v), want (0, nil)", len(sessions), err)
	}
}

func TestDeleteSessionFromDiskUnknownID(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "recording-192.0.2.9-2026-07-16T10-00-00.jsonl")
	if err := os.WriteFile(file, []byte(`{"SessionID":"other"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := deleteSessionFromDisk(dir, "missing"); err == nil {
		t.Fatal("deleting an unknown session must return an error")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("unrelated recording must survive a failed delete")
	}
}
