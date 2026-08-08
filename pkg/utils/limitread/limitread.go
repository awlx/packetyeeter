// Package limitread bounds reads of untrusted response bodies.
package limitread

import (
	"fmt"
	"io"
)

// ReadAll reads r to EOF but fails once more than limit bytes arrive, so a
// hostile or compromised upstream cannot drive unbounded memory growth.
func ReadAll(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeds %d byte limit", limit)
	}
	return data, nil
}
