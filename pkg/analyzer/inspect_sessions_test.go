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

// #67.3: a normal-but-large session record (one JSON object per line) that
// exceeds bufio's default 64 KiB token limit must still be readable and
// deletable. With the default Scanner limit, the large record errored the scan,
// which made loadSessionsFromDisk drop the session and deleteSessionFromDisk
// skip the whole file (so the delete never took effect).
func TestLargeSessionRecordingIsReadableAndDeletable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "recording-192.0.2.9-2026-07-16T11-00-00.jsonl")

	// A ~256 KiB single-line record (well past the 64 KiB default limit) plus a
	// small sibling record on the next line.
	bigPath := make([]byte, 256*1024)
	for i := range bigPath {
		bigPath[i] = 'a'
	}
	big := `{"SessionID":"big","Path":"` + string(bigPath) + `"}` + "\n"
	small := `{"SessionID":"small"}` + "\n"
	if err := os.WriteFile(file, []byte(big+small), 0o644); err != nil {
		t.Fatal(err)
	}

	sessions, err := loadSessionsFromDisk(dir)
	if err != nil {
		t.Fatalf("loadSessionsFromDisk error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected both records (incl. the large one) to load, got %d", len(sessions))
	}

	// Deleting the large record must rewrite the file, leaving only the small one.
	if err := deleteSessionFromDisk(dir, "big"); err != nil {
		t.Fatalf("delete of large record failed: %v", err)
	}
	remaining, err := loadSessionsFromDisk(dir)
	if err != nil {
		t.Fatalf("reload error: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining record after deleting the large one, got %d", len(remaining))
	}
	if sid, _ := remaining[0]["SessionID"].(string); sid != "small" {
		t.Fatalf("expected the small record to remain, got SessionID=%q", sid)
	}
}
