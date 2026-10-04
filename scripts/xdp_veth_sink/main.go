// Command xdp_veth_sink is a throwaway analyzer used only by the veth test
// scripts: it accepts the collector's StreamSignals stream and prints one line
// per received signal (id, type, and IP family; every field for scrub
// fingerprints). Given a second argument, a file (typically a FIFO), it also
// sends every line of it, a protojson Command, to all connected collectors.
// With SINK_SYNC_RULES=1 it answers a scrub collector's role signal with an
// empty replacement rule set, as the analyzer does, which the collector needs
// before it counts the stream as up.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	apiv1 "PacketYeeter/api/proto/v1"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

type collectorStream = grpc.BidiStreamingServer[apiv1.Signal, apiv1.Command]

type sink struct {
	apiv1.UnimplementedAnalyzerServiceServer
	syncRules bool

	mu      sync.Mutex
	streams map[collectorStream]struct{}
}

func (s *sink) StreamSignals(stream collectorStream) error {
	s.mu.Lock()
	s.streams[stream] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.streams, stream)
		s.mu.Unlock()
	}()

	for {
		sig, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if s.syncRules && sig.Type == apiv1.SignalType_SIGNAL_UNKNOWN && sig.GetMetadata()["role"] == "scrub" {
			s.mu.Lock()
			err := stream.Send(&apiv1.Command{
				Type:  apiv1.CommandType_COMMAND_SET_RULES,
				Rules: &apiv1.RuleSetDelta{Replace: true},
			})
			s.mu.Unlock()
			fmt.Printf("SYNCED rules err=%v\n", err)
			continue
		}
		if fp := sig.Fingerprint; sig.Type == apiv1.SignalType_SIGNAL_SCRUB_FINGERPRINT && fp != nil {
			fmt.Printf("FINGERPRINT collector=%s dst=%s proto=%d dport=%d size=%d ttl=%d src_net=%s dropped=%t packets=%d bytes=%d interval=%d\n",
				fp.CollectorId, net.IP(fp.DstIp), fp.Protocol, fp.DstPort, fp.SizeBucket, fp.TtlBucket,
				net.IP(fp.SrcNet), fp.Dropped, fp.Packets, fp.Bytes, fp.IntervalSeconds)
			continue
		}
		fam := "v4"
		if len(sig.Ip) == net.IPv6len {
			fam = "v6"
		}
		fmt.Printf("SIGNAL id=%s type=%s family=%s ip=%s\n",
			sig.Id, sig.Type, fam, net.IP(sig.Ip).String())
	}
}

func (s *sink) sendCommands(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commands:", err)
		os.Exit(1)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		var cmd apiv1.Command
		if err := protojson.Unmarshal(sc.Bytes(), &cmd); err != nil {
			fmt.Fprintln(os.Stderr, "bad command:", err)
			continue
		}
		s.mu.Lock()
		n := 0
		for st := range s.streams {
			if err := st.Send(&cmd); err == nil {
				n++
			}
		}
		s.mu.Unlock()
		fmt.Printf("SENT type=%s collectors=%d\n", cmd.Type, n)
	}
}

func main() {
	addr := ":59999"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	sk := &sink{streams: map[collectorStream]struct{}{}, syncRules: os.Getenv("SINK_SYNC_RULES") == "1"}
	if len(os.Args) > 2 {
		go sk.sendCommands(os.Args[2])
	}
	s := grpc.NewServer()
	apiv1.RegisterAnalyzerServiceServer(s, sk)
	fmt.Fprintln(os.Stderr, "sink listening on", addr)
	if err := s.Serve(lis); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}
