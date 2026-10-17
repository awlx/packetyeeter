package analyzer

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/ja4db"
	"PacketYeeter/pkg/analyzer/logthrottle"
)

type steppedClock struct {
	now time.Time
}

func (c *steppedClock) Now() time.Time {
	return c.now
}

func TestBrowserMatchLogFiresOncePerIPPerInterval(t *testing.T) {
	quietLogs(t)
	hook := new(test.Hook)
	previousHooks := logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))
	logrus.AddHook(hook)
	t.Cleanup(func() { logrus.StandardLogger().ReplaceHooks(previousHooks) })

	a := newOfflineAnalyzer(t, true)
	a.RateLimiter = nil
	db := ja4db.NewDownloader(filepath.Join(t.TempDir(), "ja4db.json"), logrus.StandardLogger())
	db.DB.Entries[benchChromeJA4] = ja4db.JA4Entry{Application: "Chrome", JA4Fingerprint: benchChromeJA4}
	a.JA4DB = db
	clock := &steppedClock{now: time.Unix(1_700_000_000, 0)}
	a.browserMatchLog = logthrottle.New(30*time.Second, 100, clock.Now)

	request := func(ip net.IP) {
		sig := &apiv1.Signal{
			Ip:   ip,
			Ja4S: benchChromeJA4,
			HttpContext: &apiv1.HTTPContext{
				Method:    "GET",
				Path:      "/",
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			},
		}
		a.processHTTPRequest(sig, ip, "AS64500", nil)
	}
	browserLogs := func() int {
		count := 0
		for _, entry := range hook.AllEntries() {
			if entry.Data["event"] == "browser_exact_ja4_match" {
				count++
			}
		}
		return count
	}

	first := net.ParseIP("192.0.2.10").To4()
	second := net.ParseIP("192.0.2.11").To4()
	for range 5 {
		request(first)
	}
	if got := browserLogs(); got != 1 {
		t.Fatalf("browser match logs for one IP inside one interval = %d, want 1", got)
	}
	request(second)
	if got := browserLogs(); got != 2 {
		t.Fatalf("browser match logs after a second IP = %d, want 2", got)
	}
	clock.now = clock.now.Add(30 * time.Second)
	request(first)
	request(first)
	if got := browserLogs(); got != 3 {
		t.Fatalf("browser match logs after the interval = %d, want 3", got)
	}
}
