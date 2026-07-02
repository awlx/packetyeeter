package analyzer

import "strings"

// Browser detection keywords and utilities
var BrowserKeywords = []string{
	"chrome", "chromium", "firefox", "safari", "edge", "edg/", "opr/", "opera", "brave", "vivaldi",
	"crios", "fxios", "android", "ios", "iphone", "ipad",
}

// IsBrowserInfo checks if the info string contains browser keywords
func IsBrowserInfo(infoLower string) bool {
	for _, kw := range BrowserKeywords {
		if strings.Contains(infoLower, kw) {
			// avoid headless matches
			if strings.Contains(infoLower, "headless") {
				continue
			}
			return true
		}
	}
	return false
}

// Bot detection keywords
var (
	BotKeywordsBasic    = []string{"bot", "crawler", "spider", "scraper", "scanner"}
	BotKeywordsExtended = []string{"bot", "crawler", "spider", "scraper", "curl", "wget", "python", "java", "go-http"}
)
