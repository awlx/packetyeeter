// Command xdp_veth_sink is a throwaway analyzer used only by
// scripts/xdp_veth_test.sh: it accepts the collector's StreamSignals stream
// and prints one line per received signal (id, type, and IP family) so the
// test can prove IPv6 flood signals actually reach the analyzer.
package main

import (
	"fmt"
	"io"
	"net"
	"os"

	apiv1 "PacketYeeter/api/proto/v1"

	"google.golang.org/grpc"
)

type sink struct {
	apiv1.UnimplementedAnalyzerServiceServer
}

func (sink) StreamSignals(stream grpc.BidiStreamingServer[apiv1.Signal, apiv1.Command]) error {
	for {
		sig, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		fam := "v4"
		if len(sig.Ip) == net.IPv6len {
			fam = "v6"
		}
		fmt.Printf("SIGNAL id=%s type=%s family=%s ip=%s\n",
			sig.Id, sig.Type, fam, net.IP(sig.Ip).String())
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
	s := grpc.NewServer()
	apiv1.RegisterAnalyzerServiceServer(s, sink{})
	fmt.Fprintln(os.Stderr, "sink listening on", addr)
	if err := s.Serve(lis); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}
