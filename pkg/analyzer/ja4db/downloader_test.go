package ja4db

import "testing"

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
