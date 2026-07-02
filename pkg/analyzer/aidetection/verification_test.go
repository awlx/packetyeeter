package aidetection

import "testing"

func TestCategorizeBotBrowserInfo(t *testing.T) {
	v := NewCrawlerVerifier(nil)
	cat := v.CategorizeBot("", "", "", "", "Chrome 120 on Windows", map[SignalType]int{}, map[SignalSource]int{}, VerificationUnknown)
	if cat != BotCategoryBrowser {
		t.Fatalf("expected browser category, got %v", cat)
	}

	cat = v.CategorizeBot("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "", "", "", "", map[SignalType]int{}, map[SignalSource]int{}, VerificationUnknown)
	if cat != BotCategoryBrowser {
		t.Fatalf("expected browser category from UA, got %v", cat)
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
