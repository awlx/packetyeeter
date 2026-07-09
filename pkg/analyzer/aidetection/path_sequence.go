package aidetection

import (
	"sort"
	"strconv"
	"strings"
)

// DetectSequentialPaths analyzes a set of request paths for evidence of
// systematic ID enumeration (e.g. /item/1000, /item/1001, /item/1002, ...
// or pagination like ?page=1, ?page=2, ?page=3). This is a much stronger
// scraper indicator than simply "many unique paths were requested" (which
// also matches a real user browsing a large, varied site).
//
// Paths are grouped by their "template" (everything except the trailing
// numeric segment or a numeric query parameter value), and a group counts
// as sequential if a large majority of its distinct values form a run of
// consecutive integers - the signature of a script walking IDs/pages in
// order, rather than a human clicking around non-adjacent content.
func DetectSequentialPaths(paths []string) bool {
	numericByTemplate := make(map[string][]int)

	for _, p := range paths {
		template, value, ok := extractTrailingNumeric(p)
		if !ok {
			continue
		}
		numericByTemplate[template] = append(numericByTemplate[template], value)
	}

	for _, values := range numericByTemplate {
		if isSequentialRun(values) {
			return true
		}
	}
	return false
}

// extractTrailingNumeric pulls a numeric ID out of a request path, either
// from the last path segment (/item/1234) or from a numeric query
// parameter value (?page=7, ?id=42). It returns a "template" key that
// identifies the surrounding context (so /item/1 and /post/1 aren't
// grouped together) and the extracted integer value.
func extractTrailingNumeric(path string) (template string, value int, ok bool) {
	base, query, _ := strings.Cut(path, "?")
	base = strings.TrimSuffix(base, "/")

	// Prefer a numeric query parameter (pagination, offsets, IDs) when present.
	if query != "" {
		for _, kv := range strings.Split(query, "&") {
			k, v, found := strings.Cut(kv, "=")
			if !found || v == "" {
				continue
			}
			if n, err := strconv.Atoi(v); err == nil {
				return base + "?" + k, n, true
			}
		}
	}

	idx := strings.LastIndex(base, "/")
	if idx < 0 {
		return "", 0, false
	}
	seg := base[idx+1:]
	if dot := strings.LastIndex(seg, "."); dot > 0 {
		seg = seg[:dot]
	}
	if seg == "" {
		return "", 0, false
	}
	n, err := strconv.Atoi(seg)
	if err != nil {
		return "", 0, false
	}
	return base[:idx], n, true
}

// isSequentialRun reports whether a set of observed integer values looks
// like a script walking IDs in order: at least 4 distinct values, with a
// large majority of adjacent (sorted) gaps equal to exactly 1.
func isSequentialRun(values []int) bool {
	uniq := dedupeInts(values)
	if len(uniq) < 4 {
		return false
	}
	sort.Ints(uniq)

	consecutive := 0
	for i := 1; i < len(uniq); i++ {
		if uniq[i]-uniq[i-1] == 1 {
			consecutive++
		}
	}
	return float64(consecutive)/float64(len(uniq)-1) >= 0.6
}

func dedupeInts(values []int) []int {
	seen := make(map[int]bool, len(values))
	out := make([]int, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
