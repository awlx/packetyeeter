package haproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/metrics"

	"github.com/dropmorepackets/haproxy-go/peers"
	"github.com/dropmorepackets/haproxy-go/peers/sticktable"
)

// Blocker is the subset of *ebpf.Maps this package depends on. It exists so
// the peer listener can be exercised in tests (including real-haproxy e2e
// tests) without a loaded eBPF program/kernel maps.
type Blocker interface {
	BlockIP(ip net.IP, reason string, meta logrus.Fields) error
}

type Server struct {
	port    int
	blocker Blocker
}

func NewServer(port int, blocker Blocker) *Server {
	return &Server{
		port:    port,
		blocker: blocker,
	}
}

func (s *Server) Start() {
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	logrus.WithField("address", addr).Info("Starting HAProxy Peer Listener")

	peer := peers.Peer{
		Addr: addr,
		HandlerSource: func() peers.Handler {
			return &handler{blocker: s.blocker}
		},
	}

	if err := peer.ListenAndServe(); err != nil {
		logrus.WithError(err).Error("Error running HAProxy Peer Listener")
	}
}

type handler struct {
	blocker Blocker
}

func (h *handler) HandleHandshake(ctx context.Context, handshake *peers.Handshake) {
	// logrus.WithField("peer", handshake.LocalPeerIdentifier).Debug("HAProxy Handshake")
}

func (h *handler) HandleUpdate(ctx context.Context, update *sticktable.EntryUpdate) {
	ipStr := update.Key.String()
	ip := net.ParseIP(ipStr)
	if ip != nil {
		h.blocker.BlockIP(ip, "HAProxy Peer Update", logrus.Fields{
			"source": "haproxy",
		})
		metrics.HAProxyBlocks.Inc()
	}
}

func (h *handler) HandleError(ctx context.Context, err error) {
	logrus.WithError(err).Error("HAProxy Peer Protocol Error")
}

func (h *handler) Close() error {
	return nil
}
