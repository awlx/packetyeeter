package grpctls

import (
	"context"
	"crypto/x509"
	"strings"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// MethodAuthorizer restricts a set of full gRPC method names to clients
// whose verified certificate carries one of the allowed names. Other methods
// pass through untouched.
type MethodAuthorizer struct {
	methods map[string]struct{}
	names   []string
	log     logrus.FieldLogger
}

// NewMethodAuthorizer returns an authorizer for methods (full names such as
// "/pkg.Service/Method"). names match a DNS SAN (case-insensitive) or the
// subject CommonName (exact).
func NewMethodAuthorizer(methods, names []string, log logrus.FieldLogger) *MethodAuthorizer {
	a := &MethodAuthorizer{methods: make(map[string]struct{}, len(methods)), names: names, log: log}
	for _, m := range methods {
		a.methods[m] = struct{}{}
	}
	return a
}

// Authorize returns a PermissionDenied status error when fullMethod is
// restricted and the caller is not one of the allowed clients.
func (a *MethodAuthorizer) Authorize(ctx context.Context, fullMethod string) error {
	if _, restricted := a.methods[fullMethod]; !restricted {
		return nil
	}
	p, ok := peer.FromContext(ctx)
	var leaf *x509.Certificate
	if ok {
		// Only VerifiedChains: PeerCertificates is whatever the client sent.
		if info, isTLS := p.AuthInfo.(credentials.TLSInfo); isTLS &&
			len(info.State.VerifiedChains) > 0 && len(info.State.VerifiedChains[0]) > 0 {
			leaf = info.State.VerifiedChains[0][0]
		}
	}
	if leaf != nil && a.allowed(leaf) {
		return nil
	}
	entry := a.log.WithField("method", fullMethod)
	if ok && p.Addr != nil {
		entry = entry.WithField("peer", p.Addr.String())
	}
	if leaf != nil {
		entry = entry.WithFields(logrus.Fields{"cn": leaf.Subject.CommonName, "dns_sans": leaf.DNSNames})
	}
	entry.Warn("Denied control-plane RPC: client certificate is not in -control-client-names")
	return status.Error(codes.PermissionDenied, "client certificate not authorized for this method")
}

func (a *MethodAuthorizer) allowed(cert *x509.Certificate) bool {
	for _, want := range a.names {
		if cert.Subject.CommonName == want {
			return true
		}
		for _, dns := range cert.DNSNames {
			if strings.EqualFold(dns, want) {
				return true
			}
		}
	}
	return false
}

// UnaryInterceptor enforces Authorize on unary RPCs.
func (a *MethodAuthorizer) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := a.Authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor enforces Authorize on streaming RPCs.
func (a *MethodAuthorizer) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := a.Authorize(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// ParseNames splits a comma-separated name list, dropping blanks.
func ParseNames(s string) []string {
	var out []string
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}
