// Package grpctls builds the TLS and mTLS credentials for the analyzer gRPC
// listener and its clients. Certificates, keys and CA bundles are re-read
// when their files change, so they can be rotated without a restart.
package grpctls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type fileStamp struct {
	mod  time.Time
	size int64
}

// fileSource caches a value parsed from one or more files and re-parses it
// when any file's modification time or size changes. A failed reload keeps
// the last good value: a half-finished rotation must not take the control
// plane down.
type fileSource[T any] struct {
	what  string
	files []string
	parse func(data [][]byte) (T, error)
	log   logrus.FieldLogger

	mu         sync.Mutex
	stamps     []fileStamp
	current    T
	lastStatEr string
}

func newFileSource[T any](what string, files []string, parse func([][]byte) (T, error), log logrus.FieldLogger) (*fileSource[T], error) {
	s := &fileSource[T]{what: what, files: files, parse: parse, log: log}
	stamps, err := statFiles(files)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", what, err)
	}
	v, err := s.read()
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", what, err)
	}
	s.stamps, s.current = stamps, v
	return s, nil
}

func (s *fileSource[T]) get() T {
	s.mu.Lock()
	defer s.mu.Unlock()

	stamps, err := statFiles(s.files)
	if err != nil {
		// Stat failures repeat on every handshake until fixed; log each distinct one once.
		if msg := err.Error(); msg != s.lastStatEr {
			s.lastStatEr = msg
			s.log.WithError(err).WithField("files", s.files).Errorf("Cannot stat %s; keeping the previously loaded one", s.what)
		}
		return s.current
	}
	s.lastStatEr = ""
	if stampsEqual(stamps, s.stamps) {
		return s.current
	}
	// Record the attempt even if it fails so a broken file is parsed and
	// logged once per change, not on every handshake.
	s.stamps = stamps
	v, err := s.read()
	if err != nil {
		s.log.WithError(err).WithField("files", s.files).Errorf("Cannot reload %s; keeping the previously loaded one", s.what)
		return s.current
	}
	s.current = v
	s.log.WithField("files", s.files).Infof("Reloaded %s", s.what)
	return v
}

// peek returns the loaded value without checking the files.
func (s *fileSource[T]) peek() T {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

func (s *fileSource[T]) read() (T, error) {
	data := make([][]byte, len(s.files))
	for i, f := range s.files {
		b, err := os.ReadFile(f)
		if err != nil {
			var zero T
			return zero, err
		}
		data[i] = b
	}
	return s.parse(data)
}

func statFiles(files []string) ([]fileStamp, error) {
	out := make([]fileStamp, len(files))
	for i, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			return nil, err
		}
		out[i] = fileStamp{mod: fi.ModTime(), size: fi.Size()}
	}
	return out, nil
}

func stampsEqual(a, b []fileStamp) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].mod.Equal(b[i].mod) || a[i].size != b[i].size {
			return false
		}
	}
	return true
}

func newKeyPairSource(certFile, keyFile string, log logrus.FieldLogger) (*fileSource[*tls.Certificate], error) {
	return newFileSource("certificate "+certFile+" with key "+keyFile, []string{certFile, keyFile}, func(d [][]byte) (*tls.Certificate, error) {
		cert, err := tls.X509KeyPair(d[0], d[1])
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}, log)
}

func newCAPoolSource(caFile string, log logrus.FieldLogger) (*fileSource[*x509.CertPool], error) {
	return newFileSource("CA bundle "+caFile, []string{caFile}, func(d [][]byte) (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(d[0]) {
			return nil, errors.New("no PEM certificates found")
		}
		return pool, nil
	}, log)
}
