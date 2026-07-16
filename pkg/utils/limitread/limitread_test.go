package limitread

import (
	"strings"
	"testing"
)

func TestReadAllWithinLimit(t *testing.T) {
	data, err := ReadAll(strings.NewReader("hello"), 5)
	if err != nil || string(data) != "hello" {
		t.Fatalf("got %q, %v; want hello, nil", data, err)
	}
}

func TestReadAllExceedsLimit(t *testing.T) {
	if _, err := ReadAll(strings.NewReader("hello world"), 5); err == nil {
		t.Fatal("want error when body exceeds limit")
	}
}
