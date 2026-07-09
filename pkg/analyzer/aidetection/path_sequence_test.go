package aidetection

import "testing"

func TestDetectSequentialPaths_NumericIDWalk(t *testing.T) {
	paths := []string{
		"/item/1001", "/item/1002", "/item/1003", "/item/1004", "/item/1005",
	}
	if !DetectSequentialPaths(paths) {
		t.Fatal("expected sequential numeric ID walk to be detected")
	}
}

func TestDetectSequentialPaths_Pagination(t *testing.T) {
	paths := []string{
		"/search?page=1", "/search?page=2", "/search?page=3", "/search?page=4",
	}
	if !DetectSequentialPaths(paths) {
		t.Fatal("expected pagination sequence to be detected")
	}
}

func TestDetectSequentialPaths_HumanBrowsing(t *testing.T) {
	// Non-consecutive, varied paths - normal human navigation.
	paths := []string{
		"/", "/about", "/contact", "/blog/my-first-post", "/pricing",
	}
	if DetectSequentialPaths(paths) {
		t.Fatal("expected normal browsing paths to NOT be flagged as sequential")
	}
}

func TestDetectSequentialPaths_SparseNumericIDs(t *testing.T) {
	// Numeric segments present but not consecutive (e.g. random product IDs
	// a real user might click through from search results).
	paths := []string{
		"/product/842", "/product/91", "/product/5510", "/product/23",
	}
	if DetectSequentialPaths(paths) {
		t.Fatal("expected sparse/non-consecutive numeric IDs to NOT be flagged as sequential")
	}
}

func TestDetectSequentialPaths_TooFewSamples(t *testing.T) {
	paths := []string{"/item/1", "/item/2", "/item/3"}
	if DetectSequentialPaths(paths) {
		t.Fatal("expected fewer than 4 distinct values to not trigger detection")
	}
}

func TestDetectSequentialPaths_DifferentTemplatesNotGrouped(t *testing.T) {
	// Sequential-looking values but under different route templates should
	// not be merged into a false sequential run.
	paths := []string{"/item/1", "/post/2", "/user/3", "/tag/4"}
	if DetectSequentialPaths(paths) {
		t.Fatal("expected different route templates to not be grouped as one sequence")
	}
}
