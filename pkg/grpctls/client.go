package grpctls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// ClientConfig configures TLS for a client dialing the analyzer. The zero
// value means plaintext.
type ClientConfig struct {
	CAFile     string // -analyzer-tls-ca: verify the analyzer with this CA; enables TLS
	CertFile   string // -analyzer-tls-cert: client certificate for mTLS
	KeyFile    string // -analyzer-tls-key
	ServerName string // -analyzer-tls-server-name: default is the host part of the dial address
}

// Enabled reports whether TLS is configured.
func (c ClientConfig) Enabled() bool { return c.CAFile != "" }

// Validate rejects inconsistent flag combinations without touching files.
func (c ClientConfig) Validate() error {
	switch {
	case c.CertFile != "" && c.KeyFile == "":
		return errors.New("-analyzer-tls-cert requires -analyzer-tls-key")
	case c.KeyFile != "" && c.CertFile == "":
		return errors.New("-analyzer-tls-key requires -analyzer-tls-cert")
	case c.CertFile != "" && c.CAFile == "":
		return errors.New("-analyzer-tls-cert requires -analyzer-tls-ca")
	case c.ServerName != "" && c.CAFile == "":
		return errors.New("-analyzer-tls-server-name requires -analyzer-tls-ca")
	}
	return nil
}

// NewClientCredentials loads the configured files and returns gRPC client
// credentials; insecure credentials when TLS is not configured. Files are
// re-read on change; the initial load must succeed.
func NewClientCredentials(c ClientConfig, log logrus.FieldLogger) (credentials.TransportCredentials, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Enabled() {
		return insecure.NewCredentials(), nil
	}
	roots, err := newCAPoolSource(c.CAFile, log)
	if err != nil {
		return nil, err
	}
	var keyPair *fileSource[*tls.Certificate]
	if c.CertFile != "" {
		if keyPair, err = newKeyPairSource(c.CertFile, c.KeyFile, log); err != nil {
			return nil, err
		}
	}
	return &reloadingClientCreds{roots: roots, keyPair: keyPair, serverName: c.ServerName}, nil
}

// reloadingClientCreds builds a fresh tls.Config per handshake because
// tls.Config.RootCAs has no callback; this picks up a rotated CA bundle
// without disabling standard verification.
type reloadingClientCreds struct {
	roots      *fileSource[*x509.CertPool]
	keyPair    *fileSource[*tls.Certificate]
	serverName string
}

func (c *reloadingClientCreds) tlsConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    c.roots.get(),
		ServerName: c.serverName,
	}
	if c.keyPair != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return c.keyPair.get(), nil
		}
	}
	return cfg
}

func (c *reloadingClientCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return credentials.NewTLS(c.tlsConfig()).ClientHandshake(ctx, authority, raw)
}

func (c *reloadingClientCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("grpctls: client credentials used for a server handshake")
}

// Info reports ServerName so gRPC uses it as the authority, which is what
// the TLS handshake verifies against.
func (c *reloadingClientCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", ServerName: c.serverName}
}

func (c *reloadingClientCreds) Clone() credentials.TransportCredentials {
	clone := *c
	return &clone
}

// OverrideServerName implements the deprecated interface method.
func (c *reloadingClientCreds) OverrideServerName(name string) error {
	c.serverName = name
	return nil
}
