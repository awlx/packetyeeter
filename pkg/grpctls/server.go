package grpctls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
)

// ServerConfig configures TLS on the analyzer gRPC listener. The zero value
// means plaintext.
type ServerConfig struct {
	CertFile     string // -tls-cert
	KeyFile      string // -tls-key
	ClientCAFile string // -tls-client-ca: require client certificates signed by this CA
}

// Enabled reports whether any TLS option is set.
func (c ServerConfig) Enabled() bool {
	return c.CertFile != "" || c.KeyFile != "" || c.ClientCAFile != ""
}

// MutualTLS reports whether client certificates are required.
func (c ServerConfig) MutualTLS() bool { return c.ClientCAFile != "" }

// Validate rejects inconsistent flag combinations without touching files.
func (c ServerConfig) Validate() error {
	switch {
	case c.CertFile != "" && c.KeyFile == "":
		return errors.New("-tls-cert requires -tls-key")
	case c.KeyFile != "" && c.CertFile == "":
		return errors.New("-tls-key requires -tls-cert")
	case c.ClientCAFile != "" && c.CertFile == "":
		return errors.New("-tls-client-ca requires -tls-cert and -tls-key")
	}
	return nil
}

// NewServerCredentials loads the configured files and returns gRPC server
// credentials, or nil when TLS is not configured. Files are re-read on
// change; the initial load must succeed.
func NewServerCredentials(c ServerConfig, log logrus.FieldLogger) (credentials.TransportCredentials, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Enabled() {
		return nil, nil
	}
	keyPair, err := newKeyPairSource(c.CertFile, c.KeyFile, log)
	if err != nil {
		return nil, err
	}
	var clientCAs *fileSource[*x509.CertPool]
	if c.ClientCAFile != "" {
		if clientCAs, err = newCAPoolSource(c.ClientCAFile, log); err != nil {
			return nil, err
		}
	}
	creds := credentials.NewTLS(newServerTLSConfig(keyPair, clientCAs))
	if clientCAs == nil {
		return creds, nil
	}
	return newTrackingServerCreds(creds, clientCAs, log), nil
}

func newServerTLSConfig(keyPair *fileSource[*tls.Certificate], clientCAs *fileSource[*x509.CertPool]) *tls.Config {
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return keyPair.get(), nil }
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2"},
		GetCertificate: getCert,
		// ClientCAs has no callback, so the per-connection config is rebuilt
		// to pick up a rotated client CA bundle.
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cfg := &tls.Config{
				MinVersion:     tls.VersionTLS12,
				NextProtos:     []string{"h2"},
				GetCertificate: getCert,
			}
			if clientCAs != nil {
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
				cfg.ClientCAs = clientCAs.get()
			}
			return cfg, nil
		},
	}
}
