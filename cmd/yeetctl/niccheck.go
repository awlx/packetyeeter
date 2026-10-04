package main

import (
	"flag"
	"fmt"
	"os"

	"PacketYeeter/pkg/nic"
)

// nicCheck runs locally, without the collector socket, so it also works
// before the collector is installed.
func nicCheck(args []string) int {
	fs := flag.NewFlagSet("nic-check", flag.ContinueOnError)
	role := fs.String("role", "", "scrub port role: outside, inside, or empty for both")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || (*role != "" && *role != "outside" && *role != "inside") {
		fmt.Fprintln(os.Stderr, "usage: yeetctl nic-check [-role outside|inside] <iface>")
		return 2
	}
	info, err := nic.Probe(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "nic-check: %v\n", err)
		return 1
	}
	nic.WriteReport(os.Stdout, info, *role)
	return 0
}
