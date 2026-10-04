package grpctls

import (
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
)

// ClientCAEnforcer is implemented by the mTLS server credentials from
// NewServerCredentials.
type ClientCAEnforcer interface {
	// CloseUntrusted re-reads the client CA bundle and, if it changed since
	// the last call, closes every connection whose client certificate no
	// longer verifies against it. It returns how many it closed.
	CloseUntrusted() int
}

// trackingServerCreds remembers each mTLS connection's verified chain.
// Authorization reads the chain from the handshake, so without this a CA
// rotation would only reach new connections and a revoked client would keep
// its open streams until it reconnected.
type trackingServerCreds struct {
	credentials.TransportCredentials
	clientCAs *fileSource[*x509.CertPool]
	log       logrus.FieldLogger

	mu      sync.Mutex
	conns   map[*trackedConn]struct{}
	checked *x509.CertPool // pool every tracked conn was last verified against
}

var errUntrustedAfterReload = errors.New("grpctls: client certificate not trusted by the reloaded client CA bundle")

type trackedConn struct {
	net.Conn
	owner *trackingServerCreds
	leaf  *x509.Certificate
	inter *x509.CertPool
	once  sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return c.Conn.Close()
}

func newTrackingServerCreds(inner credentials.TransportCredentials, clientCAs *fileSource[*x509.CertPool], log logrus.FieldLogger) *trackingServerCreds {
	return &trackingServerCreds{
		TransportCredentials: inner,
		clientCAs:            clientCAs,
		log:                  log,
		conns:                map[*trackedConn]struct{}{},
		checked:              clientCAs.peek(),
	}
}

func (c *trackingServerCreds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, auth, err := c.TransportCredentials.ServerHandshake(raw)
	if err != nil {
		return conn, auth, err
	}
	info, ok := auth.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return conn, auth, nil
	}
	chain := info.State.VerifiedChains[0]
	tc := &trackedConn{Conn: conn, owner: c, leaf: chain[0], inter: x509.NewCertPool()}
	for _, cert := range chain[1:] {
		tc.inter.AddCert(cert)
	}

	c.mu.Lock()
	// The handshake may have used a bundle CloseUntrusted already replaced;
	// check against the newest one so no connection slips past a rotation.
	if pool := c.clientCAs.peek(); pool != c.checked && !verifies(tc, pool) {
		c.mu.Unlock()
		conn.Close()
		return nil, nil, errUntrustedAfterReload
	}
	c.conns[tc] = struct{}{}
	c.mu.Unlock()
	return tc, auth, nil
}

func (c *trackingServerCreds) Clone() credentials.TransportCredentials { return c }

func (c *trackingServerCreds) CloseUntrusted() int {
	pool := c.clientCAs.get()
	c.mu.Lock()
	if pool == c.checked {
		c.mu.Unlock()
		return 0
	}
	c.checked = pool
	var untrusted []*trackedConn
	for tc := range c.conns {
		if !verifies(tc, pool) {
			untrusted = append(untrusted, tc)
		}
	}
	c.mu.Unlock()
	for _, tc := range untrusted {
		c.log.WithFields(logrus.Fields{
			"peer":     tc.RemoteAddr().String(),
			"cn":       tc.leaf.Subject.CommonName,
			"dns_sans": tc.leaf.DNSNames,
		}).Warn("Closing connection: client certificate is not trusted by the reloaded -tls-client-ca")
		tc.Close()
	}
	return len(untrusted)
}

func verifies(tc *trackedConn, roots *x509.CertPool) bool {
	_, err := tc.leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: tc.inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   time.Now(),
	})
	return err == nil
}
