package ebpf

import (
	"net"

	"github.com/cilium/ebpf"
)

type Maps struct {
	BlockedIPs          *ebpf.Map
	BlockedIPsV6        *ebpf.Map
	PendingHandshakes   *ebpf.Map
	PendingHandshakesV6 *ebpf.Map
	ICMPRates           *ebpf.Map
	ICMPRatesV6         *ebpf.Map
	BadFlags            *ebpf.Map
	BadFlagsV6          *ebpf.Map
	ConfigMap           *ebpf.Map
	UDPRates            *ebpf.Map
	UDPRatesV6          *ebpf.Map
	AllowListV4         *ebpf.Map
	AllowListV6         *ebpf.Map
	PolicyV4            *ebpf.Map
	PolicyV6            *ebpf.Map
	PolicyBlocks        *ebpf.Map
	PolicyBlocksV6      *ebpf.Map
	Events              *ebpf.Map // Perf Event Array
	Incidents           *ebpf.Map // Structured incident logging perf event array
	EgressBytes         *ebpf.Map // Cumulative egress bytes per IPv4 client
	EgressBytesV6       *ebpf.Map // Cumulative egress bytes per IPv6 client
	ScrubStats          *ebpf.Map // Per-CPU scrub verdict and slow-path counters
	TxPorts             *ebpf.Map // Scrub-mode redirect targets (inside port)
	LocalAddrsV4        *ebpf.Map // Scrub node's own addresses, never forwarded
	LocalAddrsV6        *ebpf.Map
	ScrubRules          *ebpf.Map // Rule bodies by slot
	RuleBuckets         *ebpf.Map // Per-slot rate-limit windows
	RuleMatchCounts     *ebpf.Map // Per-CPU rule matches by action
	RulesV4             *ebpf.Map // Map-in-map holding the current IPv4 rule trie
	RulesV6             *ebpf.Map
	FingerprintsA       *ebpf.Map // Scrub fingerprints, filled while the generation is odd
	FingerprintsB       *ebpf.Map // ... and while it is even
	FPOverflow          *ebpf.Map // Per-CPU packets not fingerprinted (map full)
	SynCookieStats      *ebpf.Map // Per-CPU SYN cookie events by family
	SynCookieVerifiedV4 *ebpf.Map // Sources that answered a SYN cookie challenge
	SynCookieVerifiedV6 *ebpf.Map
	RulesTrieSpecV4     *ebpf.MapSpec // Template for replacement tries
	RulesTrieSpecV6     *ebpf.MapSpec
	AllowedNets         []*net.IPNet // Userspace check
	DryRun              bool
}
