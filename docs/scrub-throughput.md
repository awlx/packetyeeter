# Scrub-mode throughput

How to measure what a scrub node (`-mode scrub`) can forward and drop, and the
reference numbers from the veth lab. See [operations.md](operations.md) for
scrub mode itself.

## What to measure

For each NIC/CPU combination you plan to deploy, measure in packets per second
(Mpps). Bits per second say little about an XDP data path.

| Scenario | Why |
| --- | --- |
| Forwarding, 64-byte frames, 0 rules | Per-packet cost of `xdp_scrub` + `bpf_fib_lookup` + devmap redirect; the worst case for clean traffic |
| Forwarding, IMIX (e.g. 7×64, 4×594, 1×1518) | Realistic mix; shows whether PCIe/memory bandwidth or the per-packet cost limits |
| Forwarding, 4096 IPv4 rules, 32 covering the tested destination, none matching | Worst-case rule matching: every packet walks 32 rules. Target: forwarding rate drops < 30% vs 0 rules |
| Dropping, 64-byte frames (blocked source, or a matching `DROP` rule) | Attack capacity: drops never touch the inside port, so this is usually well above the forwarding rate |
| Clean traffic during a spoofed-source SYN flood | Every forwarded SYN from a new 4-tuple inserts into the shared LRU `pending_handshakes` map (500k entries); measures what the inserts cost and whether clean traffic keeps its rate |

Record forward Mpps and drop Mpps separately, per scenario, with the number of
RX queues and cores used.

### Why veth numbers are not representative

`scripts/xdp_scrub_bench.sh` measures the same scenarios on veth pairs, but:

- generator, scrubber and receiver share one host and its CPUs; the generator
  usually costs more per packet than `xdp_scrub`;
- the XDP program runs in the sending CPU's softirq, not on an RX queue fed by
  RSS, and there is no NIC DMA, descriptor ring or PCIe cost;
- veth XDP builds frames from skbs, so it has none of the native driver's
  page-recycling and batching behaviour; drivers differ widely here;
- no NIC offloads (checksum, RSS hashing, GRO) are involved.

Use veth numbers only to compare versions of the code on the same machine.

## Hardware procedure

Topology: a traffic generator with two ports. Port A sends into the scrub
node's outside interface (`-i`); port B sits on the inside network and counts
what the node forwards. Route the test destination prefix via the inside port
(and give it a static neighbour entry so every packet stays on the XDP fast
path: `ip neigh replace <dst> lladdr <port B MAC> dev <inside> nud permanent`).

Node set-up:

1. Native XDP is required: do not use `-allow-generic`, and check that
   `ip link show <outside>` reports `xdp` rather than `xdpgeneric`. Generic
   XDP numbers say nothing about capacity.
2. Spread RX across cores: `ethtool -L <outside> combined <N>` and make sure
   the generator varies source IPs/ports so RSS uses all queues. Check
   `ethtool -S <outside>` per-queue counters.
3. Pin the NIC IRQs to cores on the NIC's NUMA node (stop `irqbalance` for the
   test, or set `/proc/irq/<n>/smp_affinity_list`), and keep the collector and
   anything else off those cores.
4. Run the collector without `-dry-run` (monitor mode forwards would-be drops,
   which changes what you measure), e.g.
   `packetyeeter-collector -mode scrub -i <outside> -inside-if <inside> -analyzer-addr <analyzer>`.
5. The per-source UDP limit (2500 pps) drops single-source UDP streams, so
   vary the source address over a large range in every profile. Do not
   allowlist the generator instead: allowlisted sources skip rule matching.

### TRex (stateless)

Use one TRex port per direction, e.g. port 0 → outside interface, port 1 on the
inside network.

```bash
./t-rex-64 -i                       # server
./trex-console
trex> start -f stl/udp_1pkt_simple.py -p 0 -m 100%   # minimum-size UDP
trex> start -f stl/imix.py -p 0 -m 100%
```

Copy the profiles and set the destination to an address routed via the inside
port, the destination MAC to the scrub node's outside port, and add an
`STLVmFlowVar` over the source IP (thousands of addresses) so RSS spreads the
load and the per-source UDP limit is not hit. Raise `-m` until the
port 1 RX rate stops following port 0 TX, or until TX is at line rate. The
forwarding rate is port 1 RX pps; anything lost in between is drops or ring
overflows, which the counters below tell apart.

For the drop scenario, send from a blocked source or install a matching
`DROP` rule and read the node's `drop` verdict rate (port 1 should see
nothing).

For the SYN flood, run a second stream on port 0 with random source IPs and
ports and the SYN flag (`STLVmFlowVar` on `src` and `sport`, TCP flags `S`)
next to the clean UDP stream, and compare port 1's UDP rate with and without
it.

### pktgen on a separate generator host

Without TRex, the kernel's pktgen on another Linux host connected to the
outside port works for 64-byte UDP (`samples/pktgen/pktgen_sample05_flow_per_thread.sh`
from the kernel tree, one thread per core, `-s 60`, destination MAC = the scrub
node's outside port, a source IP range). Count at the inside network's
receiver with `ip -s link` or the switch port counters. pktgen cannot do IMIX
in one run; run each size separately.

### Loading 4096 rules

Rules arrive as `COMMAND_SET_RULES` on the analyzer stream. Once the analyzer's
rule API (PushRules) is available, push them there. Until then, in a lab, run
the stand-in analyzer `scripts/xdp_veth_sink <listen-addr> <fifo>` and point the
collector at it with `-analyzer-addr`; every protojson `Command` line written
to the FIFO is sent to connected collectors. `scripts/xdp_scrub_bench.sh`
generates the worst-case set: 31 rules on a covering /16 plus 4065 /32 rules
(one on the destination), each with 8 source and 8 destination port ranges and
8 source prefixes chosen so the packet passes every check except the last
source prefix. Confirm with `packetyeeter_scrub_rules_active{family="ipv4"} == 4096`
and that `packetyeeter_scrub_rule_matches_total` does not rise during the
forwarding run.

### What to read

Collector metrics (rate over the run):

- `packetyeeter_scrub_packets_total{family,verdict}`: `forward` and `drop`
  rates are the numbers to record; `slow_path` must stay near 0, otherwise
  traffic is not on the XDP path.
- `packetyeeter_scrub_slow_path_total{reason}`: why packets left the fast
  path (`no_neigh` is the usual one in tests).
- `packetyeeter_scrub_rule_matches_total{action}`: 0 for the "none matching"
  rule scenario; equal to the drop rate for the rule-drop scenario.

Kernel counters, to cross-check and to find losses outside `xdp_scrub`:

- `ethtool -S <outside>`: RX packets, `rx_xdp_*` (names vary per driver:
  `rx_xdp_drop`, `rx_xdp_redirect`, ...), and RX ring/`rx_missed`/`rx_no_buffer`
  style counters. Missed/no-buffer means the cores did not keep up.
- `ethtool -S <inside>`: `tx_xdp_*` / XDP xmit and error counters for the
  redirected frames.
- `ip -s link show <outside>` and `<inside>`: RX/TX totals and drops.
- `mpstat -P ALL 1`: softirq time per core; all RX cores at ~100% `%soft`
  means the result is CPU-bound.

## Hardware results

| NIC | CPU | Kernel | Scenario | Packet size | Rules | Forward Mpps | Drop Mpps | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| | | | | | | | | |

## veth lab reference

From `sudo ./scripts/xdp_scrub_bench.sh` (`make bench-scrub-veth`), for
regression comparison only; see above for why these are not capacity numbers.

Machine: OrbStack VM (`yeet-dev`, Ubuntu 24.04, kernel
7.0.14-orbstack, aarch64, 7 vCPUs usable) on an Apple M2 (8 cores, 24 GB).
Multi-queue veth pairs with native veth XDP; trafgen sends 64-byte-payload
UDP (106-byte frames) and 54-byte SYN frames from CPU 1 upwards; the
destination counts and drops with a tc flower filter. Median of 3 runs of 10s.

| Scenario | Sender CPUs | Clean UDP rx pps | SYN rx pps | Forward pps | Delta |
| --- | --- | --- | --- | --- | --- |
| a: no rules | 1 | 1,936,506 | 0 | 1,936,601 | reference |
| b: 4096 rules, 32 on destination, worst-case miss (8+8 port ranges pass, 8 source prefixes miss) | 1 | 907,801 | 0 | 907,683 | -53.1% vs a |
| b2: 4096 rules, 32 on destination, each misses on its destination port | 1 | 1,458,229 | 0 | 1,457,748 | -24.7% vs a |
| c0: clean UDP only | 3 | 4,871,918 | 0 | 4,870,966 | reference |
| c1: UDP + SYN flood from one 4-tuple, 1:3 | 3 | 1,162,136 | 3,487,148 | 4,649,174 | -4.6% vs c0 |
| c2: UDP + random-source SYN flood, 1:3 | 3 | 687,149 | 2,061,752 | 2,748,301 | -40.9% vs c1 |

Reading them:

- The sender, `xdp_scrub`, the redirect and the receiver all run on the same
  CPU, so a delta here understates how much slower `xdp_scrub` itself got.
  With 32 rules covering the destination, rules that pass most checks halve
  the rate; rules that fail on an early check cost about a quarter.
- c1 vs c2 has the same packet mix; the only difference is that every SYN in c2
  is a new 4-tuple and inserts into the shared LRU `pending_handshakes` map
  (full at 500k entries within a second, so each insert also evicts). That
  costs about 40% of the forwarding rate on 3 CPUs, and clean traffic sharing
  those CPUs loses the same share.
