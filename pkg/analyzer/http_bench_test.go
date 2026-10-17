package analyzer

import (
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/analyzer/ja4db"
)

const benchChromeJA4 = "t13d1516h2_8daaf6152771_02713d6af862"

func BenchmarkProcessHTTPRequestBrowser(b *testing.B) {
	const distinctIPs = 10000
	quietLogs(b)
	a := newOfflineAnalyzer(b, true)
	a.RateLimiter = nil
	db := ja4db.NewDownloader(filepath.Join(b.TempDir(), "ja4db.json"), logrus.StandardLogger())
	db.DB.Entries[benchChromeJA4] = ja4db.JA4Entry{
		Application:    "Chrome",
		JA4Fingerprint: benchChromeJA4,
		Verified:       true,
	}
	a.JA4DB = db

	sigs := make([]*apiv1.Signal, distinctIPs)
	for i := range sigs {
		sigs[i] = &apiv1.Signal{
			Ip:   benchIP(i),
			Ja4S: benchChromeJA4,
			HttpContext: &apiv1.HTTPContext{
				Method:       "GET",
				Host:         "example.com",
				Path:         "/",
				UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
				Accept:       "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				SecFetchSite: "none",
				SecFetchMode: "navigate",
				SecFetchDest: "document",
				TlsVersion:   "TLSv1.3",
			},
		}
	}
	var next atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sig := sigs[next.Add(1)%distinctIPs]
			a.processHTTPRequest(sig, sig.Ip, "AS64500", nil)
		}
	})
}
