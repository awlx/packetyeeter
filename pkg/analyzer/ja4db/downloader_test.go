package ja4db

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func newTestLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(os.Stderr)
	l.SetLevel(logrus.ErrorLevel)
	return l
}

func newTestDownloader(t *testing.T, primaryURL, fallbackURL string) *Downloader {
	t.Helper()
	d := NewDownloader(filepath.Join(t.TempDir(), "ja4db.json"), newTestLogger())
	d.primaryURL = primaryURL
	d.fallbackURL = fallbackURL
	return d
}

func TestDownloadUsesPrimaryWhenAvailable(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-JA4DB-Version", "primary-v1")
		w.Write([]byte(`[{"application":"Chrome","ja4_fingerprint":"t13d1516h2_8daaf6152771_02713d6af862"}]`))
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("fallback should not be hit when primary succeeds")
	}))
	defer fallback.Close()

	d := newTestDownloader(t, primary.URL, fallback.URL)
	if err := d.Download(); err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	if d.DB.Source != "primary" {
		t.Fatalf("expected source=primary, got %q", d.DB.Source)
	}
	if d.DB.Version != "primary-v1" {
		t.Fatalf("expected version=primary-v1, got %q", d.DB.Version)
	}
	if len(d.DB.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(d.DB.Entries))
	}
}

func TestDownloadFallsBackOn404(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer primary.Close()

	csvBody := "Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes\n" +
		"Chromium Browser,,,,t13d1516h2_8daaf6152771_02713d6af862,,,,,,\n"
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(csvBody))
	}))
	defer fallback.Close()

	d := newTestDownloader(t, primary.URL, fallback.URL)
	if err := d.Download(); err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	if d.DB.Source != "fallback" {
		t.Fatalf("expected source=fallback, got %q", d.DB.Source)
	}
	entry, ok := d.DB.Entries["t13d1516h2_8daaf6152771_02713d6af862"]
	if !ok {
		t.Fatalf("expected fallback entry to be indexed")
	}
	if entry.Application != "Chromium Browser" {
		t.Fatalf("expected application=Chromium Browser, got %q", entry.Application)
	}
}

func TestDownloadFailsWhenBothSourcesFail(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fallback.Close()

	d := newTestDownloader(t, primary.URL, fallback.URL)
	if err := d.Download(); err == nil {
		t.Fatalf("expected Download() to fail when both sources fail")
	}
}

func TestParseJA4PlusCSV(t *testing.T) {
	body := []byte(
		"Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes\n" +
			",Python,,,t13i181000_85036bcba153_d41ae481755e,,,,,,\n" +
			"Chromium Browser,,,,t13d1516h2_8daaf6152771_02713d6af862,,,,,,\n" +
			",,,,,,,,,,\n", // blank row should be skipped
	)

	entries, err := parseJA4PlusCSV(body)
	if err != nil {
		t.Fatalf("parseJA4PlusCSV() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (blank row skipped), got %d", len(entries))
	}
	if entries[0].Library != "Python" {
		t.Fatalf("expected first entry library=Python, got %q", entries[0].Library)
	}
	if entries[1].Application != "Chromium Browser" {
		t.Fatalf("expected second entry application=Chromium Browser, got %q", entries[1].Application)
	}
}

func TestIsNotFoundErr(t *testing.T) {
	if !isNotFoundErr(&notFoundError{statusCode: http.StatusNotFound}) {
		t.Fatal("expected 404 to be recognized as not-found")
	}
	if isNotFoundErr(&notFoundError{statusCode: http.StatusInternalServerError}) {
		t.Fatal("expected 500 to not be recognized as not-found")
	}
	if isNotFoundErr(nil) {
		t.Fatal("expected nil error to not be recognized as not-found")
	}
}

func TestDeriveAppCategoryBrowser(t *testing.T) {
	entry := JA4Entry{Application: "Chrome", Library: "", Device: "Windows"}
	if cat := deriveAppCategory(entry); cat != "browser" {
		t.Fatalf("expected browser, got %q", cat)
	}
}

func TestIsBrowserInfo(t *testing.T) {
	if !IsBrowserInfo("chrome 120 [verified]") {
		t.Fatalf("expected chrome to be browser info")
	}
	if IsBrowserInfo("headlesschrome 120") {
		t.Fatalf("expected headlesschrome to be ignored")
	}
}

func TestDeriveAppCategoryScript(t *testing.T) {
	entry := JA4Entry{Application: "curl", UserAgentString: "curl/7.88.0"}
	if cat := deriveAppCategory(entry); cat != "script" {
		t.Fatalf("expected script, got %q", cat)
	}
}

// TestJA4WildcardRequiresABSegments verifies that the JA4 wildcard fallback
// (EntriesByJA4Prefix / LookupWithTypeResult) requires a match on both the
// 'a' and 'b' segments of the fingerprint, not just the coarse 'a' segment.
// Before the fix, any fingerprint sharing only the 'a' segment with an
// indexed entry returned that entry as an arbitrary "wildcard_tls" match,
// letting unrelated clients (including attacker-crafted ClientHellos) collide
// with browser/bot DB entries that merely share the coarse prefix.
func TestJA4WildcardRequiresABSegments(t *testing.T) {
	d := NewDownloader(filepath.Join(t.TempDir(), "ja4db.json"), newTestLogger())

	browserEntry := JA4Entry{
		Application:    "Chrome",
		JA4Fingerprint: "t13d1516h2_8daaf6152771_02713d6af862",
	}
	d.applyEntries([]JA4Entry{browserEntry}, "test", "v1")

	t.Run("same a, different b: no wildcard match", func(t *testing.T) {
		// Shares only the 'a' segment (t13d1516h2) with the indexed entry.
		fp := "t13d1516h2_ffffffffffff_ffffffffffff"
		res, found := d.LookupWithTypeResult(fp, "ja4")
		if found {
			t.Fatalf("expected no match for fingerprint sharing only the 'a' segment, got match_type=%q entry=%+v", res.MatchType, res.Entry)
		}
	})

	t.Run("same a and b, different c: wildcard match", func(t *testing.T) {
		// Shares the 'a' and 'b' segments; only 'c' (extension hash) differs.
		fp := "t13d1516h2_8daaf6152771_ffffffffffff"
		res, found := d.LookupWithTypeResult(fp, "ja4")
		if !found {
			t.Fatalf("expected wildcard match for fingerprint sharing 'a' and 'b' segments")
		}
		if res.MatchType != "wildcard_tls" {
			t.Fatalf("expected match_type=wildcard_tls, got %q", res.MatchType)
		}
		if res.Entry.Application != "Chrome" {
			t.Fatalf("expected matched entry application=Chrome, got %q", res.Entry.Application)
		}
	})

	t.Run("exact fingerprint: exact match", func(t *testing.T) {
		res, found := d.LookupWithTypeResult(browserEntry.JA4Fingerprint, "ja4")
		if !found || res.MatchType != "exact" {
			t.Fatalf("expected exact match, got found=%v match_type=%q", found, res.MatchType)
		}
	})
}
