// Package grpctlstest issues throwaway CAs and certificates for TLS tests.
package grpctlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is an in-memory certificate authority.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// NewCA creates a self-signed CA.
func NewCA(t testing.TB, cn string) *CA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return &CA{Cert: cert, Key: key, CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Leaf is an issued certificate and key, PEM-encoded.
type Leaf struct {
	CertPEM, KeyPEM []byte
}

// IssueServer issues a server-auth certificate for the given names; IP
// literals become IP SANs.
func (ca *CA) IssueServer(t testing.TB, cn string, names ...string) Leaf {
	t.Helper()
	return ca.issue(t, cn, names, x509.ExtKeyUsageServerAuth)
}

// IssueClient issues a client-auth certificate whose names become DNS SANs.
func (ca *CA) IssueClient(t testing.TB, cn string, names ...string) Leaf {
	t.Helper()
	return ca.issue(t, cn, names, x509.ExtKeyUsageClientAuth)
}

func (ca *CA) issue(t testing.TB, cn string, names []string, usage x509.ExtKeyUsage) Leaf {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("issue %s: %v", cn, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return Leaf{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

// WriteCA writes the CA certificate to dir/name.pem and returns the path.
func (ca *CA) WriteCA(t testing.TB, dir, name string) string {
	t.Helper()
	return WriteFile(t, filepath.Join(dir, name+".pem"), ca.CertPEM)
}

// Write writes the leaf to dir/name.crt and dir/name.key.
func (l Leaf) Write(t testing.TB, dir, name string) (certPath, keyPath string) {
	t.Helper()
	return WriteFile(t, filepath.Join(dir, name+".crt"), l.CertPEM),
		WriteFile(t, filepath.Join(dir, name+".key"), l.KeyPEM)
}

// WriteFile writes data and bumps the mtime so reloaders see a change even on
// filesystems with coarse timestamps.
func WriteFile(t testing.TB, path string, data []byte) string {
	t.Helper()
	var next time.Time
	if fi, err := os.Stat(path); err == nil {
		next = fi.ModTime().Add(2 * time.Second)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if !next.IsZero() {
		if err := os.Chtimes(path, next, next); err != nil {
			t.Fatalf("chtimes %s: %v", path, err)
		}
	}
	return path
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}
