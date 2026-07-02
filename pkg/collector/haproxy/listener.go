package haproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/metrics"

	"github.com/dropmorepackets/haproxy-go/peers"
	"github.com/dropmorepackets/haproxy-go/peers/sticktable"
)

type Server struct {
	port int
	maps *ebpf.Maps
}

func NewServer(port int, maps *ebpf.Maps) *Server {
	return &Server{
		port: port,
		maps: maps,
	}
}

func (s *Server) Start() {
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	logrus.WithField("address", addr).Info("Starting HAProxy Peer Listener")

	peer := peers.Peer{
		Addr: addr,
		HandlerSource: func() peers.Handler {
			return &handler{maps: s.maps}
		},
	}

	if err := peer.ListenAndServe(); err != nil {
		logrus.WithError(err).Error("Error running HAProxy Peer Listener")
	}
}

type handler struct {
	maps *ebpf.Maps
}

func (h *handler) HandleHandshake(ctx context.Context, handshake *peers.Handshake) {
	// logrus.WithField("peer", handshake.LocalPeerIdentifier).Debug("HAProxy Handshake")
}

func (h *handler) HandleUpdate(ctx context.Context, update *sticktable.EntryUpdate) {
	ipStr := update.Key.String()
	ip := net.ParseIP(ipStr)
	if ip != nil {
		h.maps.BlockIP(ip, "HAProxy Peer Update", logrus.Fields{
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
