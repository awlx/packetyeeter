# Scrub-mode hardware: NICs, drivers and expected throughput

Which NICs and drivers suit a scrub node (`-mode scrub`), how fast `xdp_scrub`
should run on them, and how to tune the host. The throughput figures are a
**model**, built from published XDP measurements and the per-packet cost of
`xdp_scrub` measured in the veth lab. Measure on the real hardware before
relying on them ([scrub-throughput.md](scrub-throughput.md)), and record the
results there.

`yeetctl nic-check <iface>` runs the checks below on a host and prints the
model's prediction for its driver.

## Summary

- **Clean forwarding:** about **2.5–5 Mpps per core** on mlx5/ice/i40e-class
  NICs, falling to **1.3–2.6 Mpps per core** with 4096 rules whose
  destinations cover the traffic.
- **Dropping (matched rule):** about **4–11 Mpps per core**.
- **Random-source SYN flood (forwarded):** about **1–2 Mpps per core**.
- **Line rate at 64-byte frames:**
  - 10 GbE (14.9 Mpps): 3–6 cores.
  - 25 GbE (37.2 Mpps): 8–15 cores.
  - 100 GbE (148.8 Mpps): out of reach for one host's CPUs and for most
    NICs' own packet-rate limits.
- **Line rate at IMIX:**
  - 25 GbE: 2–4 cores.
  - 100 GbE (32.7 Mpps): 7–13 cores for clean traffic.
- **Q-3 starting target** (mlx5 or ice), to confirm on hardware:
  - a 25 GbE node forwards IMIX at line rate with 4096 rules on at most 8
    cores;
  - it drops 64-byte traffic matching rules at 25 GbE line rate (37 Mpps) on
    at most 8 cores;
  - it forwards at least 3 Mpps of clean 64-byte traffic per core with no
    rules.

  Below these figures, the node or its tuning is wrong. Above them, the
  model was pessimistic.
- **NICs to test first:** NVIDIA ConnectX-6 Dx/ConnectX-7 (`mlx5_core`) and
  Intel E810 (`ice`). They are the only families with every XDP feature
  scrub mode can use, plus hardware drop filters.
- **To avoid:**
  - generic (skb) XDP;
  - mlx4 or nfp as the inside port;
  - virtual functions without XDP (`iavf`, `ixgbevf`).

## Driver capability matrix

Mainline as of 7.3-rc5, read from the driver sources (`xdp_features`
assignments and `xdp_metadata_ops` tables); "since" is the first release with
the feature. Distribution kernels backport selectively, so ask the running
kernel: `yeetctl nic-check` reads the netdev netlink family (Linux 6.3+).

Scrub mode needs, on the **outside** port, native XDP with `XDP_REDIRECT`
("redir"), and on the **inside** port `ndo_xdp_xmit` ("xmit", the redirect
target). Many drivers only advertise xmit while an XDP program is attached to
the port, which is why the collector attaches `xdp_pass_inside` there.

| Driver (NIC) | Native XDP | redir | xmit | Multi-buffer (RX_SG) | AF_XDP zero-copy | RX metadata kfuncs | Scrub roles |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mlx5_core` (ConnectX-4…7, BlueField) | 4.9 | yes | yes, with prog | yes (5.18; striding RQ ~6.4) | yes (5.3) | hash, timestamp, vlan (6.3/6.8) | both |
| `mlx4_en` (ConnectX-3) | 4.8 | yes | **no** | no | no | hash, timestamp | outside only |
| `ice` (E810) | 5.5 | yes | yes, with prog | yes (6.3) | yes (5.5) | hash, timestamp, vlan (6.8) | both |
| `i40e` (X710/XL710/XXV710) | 4.13 | yes | yes, with prog | yes (6.4) | yes (4.20) | none | both |
| `ixgbe` (82599/X520/X540/X550) | 4.12 | yes | yes, with prog | no | yes (4.20) | none | both |
| `igb` / `igc` (I210/I350, I225/I226) | 5.10 / 5.13 | yes | yes, with prog | no | igb 6.14, igc 5.14 | igc: hash, timestamp (6.5) | both (1 GbE) |
| `bnxt_en` (NetXtreme-C/E) | 4.11 | yes | yes, with prog | yes (5.19) | no | hash (7.1) | both |
| `sfc` (Solarflare/AMD X2) | 5.5 | yes | yes | no | no | none | both |
| `qede` (QLogic FastLinQ) | 4.10 | yes | yes (5.9) | no | no | none | both; driver orphaned |
| `idpf` (Intel IPU/E2000) | 6.18 | yes | yes | yes | yes | hash (6.18), timestamp (7.0) | both |
| `ena` (AWS) | 5.6 | yes | yes (5.11) | no (upstream) | no (upstream) | none | both |
| `gve` (Google gVNIC) | 6.4 | yes | yes | no | yes (6.4) | timestamp (6.19) | both |
| `mana` (Azure) | 5.17 | yes | yes (6.0) | no | no | none | both |
| `virtio_net` | 4.10 | yes | yes, with prog | yes (6.3) | yes (6.11) | hash (6.10, with device hash report) | both (labs, VMs) |
| `veth` | 4.14 | yes | yes, peer with prog or GRO | yes (5.18) | no | hash, timestamp, vlan | lab only |
| `nfp` (Netronome Agilio) | 4.10 | some firmware | **no** | no | yes (NFD3) | none | outside only; driver in odd-fixes |
| `ixgbevf` | 4.17 | **no** | no | no | no | none | none |
| `iavf` | **none** | – | – | – | – | – | none (generic only) |
| `r8169` (Realtek, lab host) | **none** | – | – | – | – | – | none (generic only) |

Other notes:

- **Hardware XDP offload** (`xdpoffload`) exists only in `nfp`, which is in
  maintenance. Do not plan on it. NIC hardware filtering is done with tc flower
  or ethtool ntuple instead (see [hardware pre-drop](#design-nic-hardware-pre-drop-of-flowspec-like-rules)).
- **Single-buffer MTU.** Without multi-buffer support, native XDP refuses
  MTUs above about one page minus headroom:

  | Driver | Max MTU |
  | --- | --- |
  | `i40e`/`ice` | 3046 |
  | `mlx5`, upstream `ena` | ~3498 |
  | `virtio_net` | ~3506 |

  `xdp_scrub` is a single-buffer program (no `xdp.frags`), so scrub ports must
  stay at or below these MTUs (1500 is fine) even on drivers that support
  multi-buffer.
- **LRO and HW-GRO** must be off. `mlx5`, `ixgbe` and `virtio_net` refuse
  native XDP otherwise.

## Performance model

### Formula

Per packet, one core spends:

```
t = t_drv_rx              driver RX, descriptor and page recycling, XDP dispatch
  + t_bpf × s             xdp_scrub itself (measured), scaled to the server CPU
  + t_drv_tx              redirect: devmap enqueue, bulk flush, TX descriptor, completion
                          (forwarded packets only)
per-core Mpps = 1000 / t[ns]
```

- `t_drv_rx` = 1 / (published per-core `XDP_DROP` rate with a trivial
  program).
- `t_drv_tx` = 1 / (published per-core devmap `XDP_REDIRECT` rate) −
  `t_drv_rx`.
- `t_bpf` is `xdp_scrub`'s own run time from `kernel.bpf_stats_enabled`. It
  includes `bpf_fib_lookup` and all map lookups, but not the devmap flush,
  which runs after the program returns.

### Driver inputs

Independent measurements unless marked [vendor].

| Driver | XDP_DROP / core | devmap REDIRECT / core | `t_drv_rx` | `t_drv_tx` |
| --- | --- | --- | --- | --- |
| mlx5 (CX-5, Xeon E5-1650 v4 3.6 GHz) | 24 Mpps [1]; CX-6 Dx 20–32 Mpps depending on kernel [6][5, vendor] | 8.65 Mpps [2]; 8.4 Mpps on 5.6 [3]; 7 Mpps at 2.5 GHz [vendor, 4] | 31–50 ns | 60–100 ns |
| i40e / ixgbe (E5-1650 v4, retpoline) | ixgbe 10.1 Mpps with KPTI+retpoline [7] | 6.7 / 6.9 Mpps [8] | 45–100 ns | 50–110 ns |
| ice, bnxt_en | no published XDP rates | – | assumed like i40e | assumed like i40e |
| ena, gve, virtio_net | no published XDP rates | – | 80–200 ns (assumed) | 100–400 ns (assumed) |

### Cross-checks

- **Generic XDP** costs about 39 ns more per packet than native on mlx5
  (8.15 vs 19.8 Mpps drop [9]), on top of the skb allocation that native XDP
  avoids. For a forwarding program the difference is larger, because the
  redirect goes through `dev_queue_xmit`.
- **`xdp_fwd`**, i.e. `bpf_fib_lookup` plus devmap redirect with nothing else,
  runs at 5.2–5.4 Mpps per core on the CX-5 testbed (~190 ns) [2]. With a full
  BGP table (752k routes) it drops to 3.45 Mpps (~290 ns). `xdp_scrub` must
  come in below that rate.

  A scrub node normally has a handful of routes. Keep it that way: a full
  table on the node costs about 100 ns per packet in `bpf_fib_lookup` alone.

### Measured xdp_scrub cost

`BPF_STATS=1 ./scripts/xdp_scrub_bench.sh`: OrbStack VM on an Apple M2,
kernel 7.0, IPv4, 64-byte UDP payload. The values are medians, with the
fastest and slowest runs in brackets.

| Scenario | `xdp_scrub` ns/packet | Runs |
| --- | --- | --- |
| a: forward, no rules | 106 (94–122) | 11 |
| b: forward, 4096 rules, 32 on the destination, worst-case miss | 318 (282–350) | 5 |
| d: drop by a matching DROP rule | 67 (60–85) | 9 |
| c1, 1 CPU: 1 UDP : 3 SYN from one 4-tuple | 133 (125–134) | 4 |
| c2, 1 CPU: 1 UDP : 3 SYN from random sources | 440 (394–515) | 4 |
| c2, 3 CPUs (shared LRU contention) | 1340 (944–2356) | 5 |

Runs that landed on efficiency cores (up to 2–9× slower) are left out of the
ranges.

In c2, each random-source SYN costs about 550 ns, against about 140 ns for a
SYN of a known 4-tuple. The extra ~400 ns is the insert into the full,
evicting LRU. With 3 CPUs inserting into the same map it rises to well over
1 µs per packet. This is the most expensive traffic `xdp_scrub` handles, and
spoofed-source UDP or ICMP floods hit the same shared-LRU insert in
`udp_rates`/`icmp_rates`.

Verifier size of `xdp_scrub` (`progstats`): 6080 translated instructions, 271k instructions
verified (6155 and 272k before the redirect change below). Instruction counts
say little about run time: almost all of the cost is in helper calls and map
lookups, not in straight-line instructions.

#### What each packet pays for

Forwarded clean UDP pays for 10 map lookups or updates, one `bpf_fib_lookup`,
one `bpf_ktime_get_ns` and one devmap redirect:

| Map | Type |
| --- | --- |
| `config_map` | array |
| `local_addrs` | hash |
| allowlist | LPM |
| rules | array of maps + LPM |
| policy | LPM |
| `blocked_ips` | hash |
| `udp_rates` | shared LRU, atomic add |
| fingerprint | per-CPU hash |
| `scrub_stats` | per-CPU array |

The rule-heavy scenario adds the walk over the rules covering the
destination: 32 rules × (8+8 port ranges + 8 source prefixes).

#### Scaling to a server CPU

`s` scales Apple M2 performance-core time to a 2.5–3.5 GHz server core. It is
assumed to be 1.0–1.6, and it is the largest single uncertainty in the model.
The M2 core has very high IPC and large caches, while the server core gains
from a warm DDIO LLC. Two caveats apply to the VM measurement:

- The VM's vCPUs can land on the M2's efficiency cores, so single runs
  scatter by up to ±30%.
- The VM has no NIC, so `t_bpf` there excludes the cache misses that real
  packet data and large maps cause.

### Predictions

`s` = 1.0–1.6. The ranges combine the low ends and the high ends of every
input, so they are wide on purpose: the true value should fall inside, not at
the midpoint.

| Driver family | forward | forward, 4096 rules | rule drop | random-source SYN flood |
| --- | --- | --- | --- | --- |
| NVIDIA ConnectX-4/5/6/7 (`mlx5_core`) | 2.9–5.2 | 1.4–2.6 | 5.4–11.0 | 1.0–2.0 |
| Intel E810 (`ice`), assumed like i40e | 2.6–5.3 | 1.3–2.6 | 4.4–10.0 | 1.0–2.0 |
| Intel X710/XXV710 (`i40e`) | 2.6–5.1 | 1.3–2.6 | 4.4–9.5 | 1.0–2.0 |
| Intel 82599/X5x0 (`ixgbe`) | 2.5–5.0 | 1.3–2.6 | 4.2–9.1 | 1.0–2.0 |
| Broadcom (`bnxt_en`), assumed | 2.4–4.8 | 1.3–2.5 | 4.2–9.1 | 1.0–2.0 |
| AWS ENA / gVNIC, assumed | 1.7–3.6 | 1.0–2.1 | 3.5–7.1 | 0.8–1.7 |
| virtio-net, assumed | 1.3–3.0 | 0.9–1.9 | 3.0–7.1 | 0.7–1.6 |
| veth (lab) | 1.1–2.2 | 0.8–1.6 | 2.3–4.8 | 0.7–1.3 |

All figures are Mpps per core.

Two checks support the table:

- The veth row matches the veth bench: 1.6–2.0 Mpps forward, measured on one
  CPU that also runs the sender.
- The mlx5 forward ceiling of 5.2 Mpps stays just below `xdp_fwd`'s measured
  5.3 Mpps, as it must, since `xdp_scrub` does strictly more work per packet.

The NIC dominates less than one might expect: `xdp_scrub` itself is 40–70%
of the per-packet time on a good NIC. Cheaper rules and map lookups pay off
more than a faster NIC, up to the NIC's own limits.

### Cores for line rate

Line rate (Mpps) counts 20 bytes of preamble and inter-frame gap per frame.
IMIX is 7×64, 4×594, 1×1518 (mean frame 361.8 bytes).

| Link | 64 B | IMIX |
| --- | --- | --- |
| 10 GbE | 14.88 | 3.27 |
| 25 GbE | 37.20 | 8.18 |
| 40 GbE | 59.52 | 13.09 |
| 100 GbE | 148.81 | 32.74 |

Cores needed, at the mlx5/ice-class per-core range above (best–worst case):

| Link | forward | forward, 4096 rules | rule drop | random-source SYN flood |
| --- | --- | --- | --- | --- |
| 10 GbE | 3–6 / 1–2 | 6–12 / 2–3 | 2–4 / 1 | 8–16 / 2–4 |
| 25 GbE | 8–15 / 2–4 | 15–29 / 4–7 | 4–9 / 1–2 | 19–39 / 5–9 |
| 40 GbE | 12–24 / 3–6 | 23–46 / 5–10 | 6–14 / 2–3 | 30–62 / 7–14 |
| 100 GbE | 29–59 / 7–13 | 57–114 / 13–25 | 14–34 / 3–8 | 73–154 / 17–34 |

Each cell is cores for 64 B / cores for IMIX.

These figures assume RSS spreads the flood evenly. They ignore the shared-LRU
contention that makes the SYN-flood column worse with more cores, and the
NIC/PCIe ceilings below.

### Limits outside the model

- **NIC and PCIe packet-rate ceilings.** A ConnectX-5 tops out at about
  115–126 Mpps of 64-byte drop with CQE compression [1][10]. Forwarding uses
  the PCIe link in both directions: same-NIC forwarding hit the PCIe limit at
  70 Mpps [1]. Plan 100 GbE scrub nodes for IMIX-heavy floods, or for 64-byte
  floods dropped in NIC hardware, not for 148 Mpps through XDP.
- **Multi-core scaling.** Per-CPU state (handshake LRU, counters,
  fingerprints) scales linearly. Two kinds of state are shared:
  - `udp_rates`/`icmp_rates` (per-source counters with an atomic add);
  - inserts into shared LRU maps.

  A single source spread over many queues bounces one cache line between
  cores. A random-source UDP or ICMP flood inserts into the shared LRU for
  every packet, the same cost as the random-source SYN case. In the veth lab,
  3 CPUs in that mix ran 40% slower than without the inserts
  ([scrub-throughput.md](scrub-throughput.md)).
- **RX ring size.** On mlx5, 6-core redirect rose from 29.8 to 46.1 Mpps when
  RX rings shrank from 1024 to 256 descriptors, because the working set fit
  DDIO [2]. Larger rings absorb bursts but cost peak rate.
- **Kernel version.** mlx5 single-core drop moved between 20 and 32 Mpps
  across 5.15–6.16 [5][6]. Re-measure after kernel upgrades.

## Tuning guide

In order of impact:

1. **Native XDP on both ports.** The collector refuses generic XDP unless you
   pass `-allow-generic`, and logs each port's mode and driver features at
   start-up ("Scrub port attached"). With `-allow-generic`, if the inside
   port falls back to generic, the outside port is attached in generic mode
   too, because a native redirect into a port without native XDP is dropped.
   Check the mode with `ip link show <port>`: `xdp` means native and
   `xdpgeneric` means generic.
2. **Turn off LRO and HW-GRO.** Run `ethtool -K <port> lro off rx-gro-hw off`;
   native XDP refuses to attach otherwise.
3. **Keep the MTU at or below the single-buffer limit** (table above).
4. **Spread RX over cores:**
   - Run `ethtool -L <outside> combined <n>`, with n = the cores you give to
     scrubbing, all on the NIC's NUMA node.
   - Check `ethtool -x <outside>` for an even indirection table.
   - Keep `rxhash` on.

   Spoofed floods spread well across queues. A single-source flood lands on
   one queue, but it is also the case the per-source limits drop cheaply.
5. **Pin IRQs:**
   - Stop `irqbalance`, or ban the NIC's IRQs from it.
   - Set `/proc/irq/<n>/smp_affinity_list` one-to-one from queues to cores on
     the NIC's NUMA node.
   - Keep the collector process, the analyzer and everything else off those
     cores.

   `yeetctl nic-check` warns about IRQs on remote-NUMA CPUs.
6. **RX ring size.** 512–1024 descriptors is a good start (`ethtool -G <port> rx 1024`):
   - Raise it if `rx_missed`/`rx_out_of_buffer`-style counters grow in short
     bursts while the cores are not saturated.
   - Lower it (256–512) if the cores are saturated and the LLC miss rate is
     high.
7. **NAPI.** Defaults are right for XDP: interrupt mitigation plus NAPI
   polling already batches up to 64 packets per poll.
   - Busy polling (`net.core.busy_poll`, `SO_PREFER_BUSY_POLL`) applies to
     sockets and AF_XDP, not to `xdp_scrub`.
   - Threaded NAPI (`echo 1 > /sys/class/net/<port>/threaded`) lets the
     scheduler move RX processing, which only helps when the cores also run
     other work.
   - Leave `napi_defer_hard_irqs`/`gro_flush_timeout` at 0 unless you measure
     a gain.
8. **mlx5 specifics:**
   - Keep `rx_striding_rq` on (the default on most NICs).
   - Enable `rx_cqe_compress` on PCIe-bound 100 GbE setups
     (`ethtool --set-priv-flags <port> rx_cqe_compress on`). It was needed for
     the 115 Mpps result [1].
   - ntuple filters are unavailable in switchdev mode.
9. **Routes.** Keep the FIB on the scrub node small (default route plus the
   inside prefixes). `bpf_fib_lookup` against a full table costs about
   100 ns per packet [2].
10. **CPU mitigations and frequency.** Retpoline and KPTI cost indirect calls
    in the driver path. Fix the CPU frequency governor to `performance`, since
    floods arrive suddenly.

## NICs to buy or test first

1. **NVIDIA ConnectX-6 Dx or ConnectX-7 (`mlx5_core`), 25/100 GbE.**
   - The most measured XDP driver, with every feature (redirect target, multi-buffer, AF_XDP
     zero-copy, all RX metadata kfuncs).
   - tc flower hardware drop in NIC mode, and 1024 ethtool ntuple rules.
   - The first hardware entry for [scrub-throughput.md](scrub-throughput.md).
2. **Intel E810 (`ice`), 25/100 GbE.** Full XDP feature set and Flow Director
   with up to 16k ntuple drop filters, but no published XDP rates. Measuring it
   closes the model's biggest gap.
3. **Intel X710/XXV710 (`i40e`), 10/25 GbE** for small sites: mature XDP, but
   no RX metadata and older silicon.
4. **Broadcom (`bnxt_en`)** only if already deployed: XDP works, but there are
   no published rates and tc offload depends on firmware.

Cloud and virtual NICs (`ena`, `gve`, `mana`, `virtio_net`) work but are bound
by the provider's PPS allowance. They suit labs and small deployments, not
volumetric scrubbing. The lab host (`lab`, Realtek RTL8111 on `r8169`, one
queue, 1 GbE) has no native XDP and can only run scrub mode with
`-allow-generic`.

## yeetctl nic-check

```bash
sudo yeetctl nic-check -role outside eth0
sudo yeetctl nic-check -role inside eth1
```

Runs locally, without the collector, and only reads state:

- **Driver identity:** driver, firmware and bus (ethtool ioctl).
- **XDP:** the attached program and its mode (netlink), and the driver's XDP
  and RX metadata features (netdev netlink, 6.3+).
- **Queues and IRQs:** queues against CPUs on the NIC's NUMA node, and IRQ
  affinity.
- **ethtool settings:** `irqbalance`, ring sizes, channels and offloads
  (`ethtool -g/-l/-k`, when ethtool is installed).
- **Model output:** the per-core prediction for the driver, plus the cores
  needed for 64-byte and IMIX line rate at the link speed.

It warns about:

- generic mode;
- missing redirect or xmit support for the given role;
- LRO/HW-GRO on;
- an MTU above the single-buffer limit;
- a single RX queue;
- remote-NUMA IRQs.

## What packetyeeter uses from the drivers

- **Devmap redirect with bulking.**
  - `xdp_scrub` redirects through a `DEVMAP_HASH` (`tx_ports`), so frames are
    queued per CPU and handed to the inside driver's `ndo_xdp_xmit` 16 at a
    time, at the end of each NAPI poll.
  - The map-less `bpf_redirect(ifindex)` is bulked too since 5.6, but adds a
    device lookup per packet.
  - `xdp_scrub` calls `bpf_redirect_map` once per packet, with `XDP_PASS` as
    the miss action. That call doubles as the check that the FIB's egress
    port is a scrub port, before the frame is rewritten.

    Before, a separate lookup did that check, so this saves one devmap hash
    lookup per forwarded packet (an estimated 5–10 ns). The VM measurements
    could not resolve the difference from noise.
- **Driver feature checks.** At start-up the collector logs each scrub port's
  attach mode and its `xdp-features`/RX metadata features. It warns when:
  - the outside driver lacks `XDP_REDIRECT`;
  - the inside driver lacks `ndo_xdp_xmit`, in which case the kernel drops
    every redirected frame (`-EOPNOTSUPP` in `__xdp_enqueue`) while
    `xdp_scrub` still counts it as forwarded.
- **RX metadata kfuncs are not used, on purpose.**
  - `bpf_xdp_metadata_rx_hash` would give the NIC's RSS hash for free, but
    `xdp_scrub` computes no hash of its own: map hashing happens inside the
    kernel's map code and cannot take a precomputed hash.
  - An RSS hash cannot replace an exact map key without false matches between
    sources.
  - Programs that call these kfuncs must be loaded bound to one device
    (`BPF_F_XDP_DEV_BOUND_ONLY`), which `xdp_scrub` would need per outside
    port.
  - The kfuncs need 6.3+ (VLAN 6.8+), and i40e, ixgbe, ena and sfc implement
    none.

  The VLAN-tag kfunc could later let tagged outside ports stay on the fast
  path. That is a feature change, not an optimisation.
- **Multi-buffer and AF_XDP zero-copy are not used.** Scrub ports run at
  standard MTUs, and the data path never leaves the kernel.

## Design: NIC hardware pre-drop of FlowSpec-like rules

Not implemented; this is a proposal for review.

### Idea

The rules pushed with `COMMAND_SET_RULES` are FlowSpec-like. Those with action
`DROP` that use only fields NIC classifiers support could also be installed
as hardware filters, which drop before the packet costs PCIe bandwidth, a
descriptor or any CPU. The supported fields are:

- destination and source prefix;
- protocol;
- single ports, or port ranges that expand to a few entries;
- TCP flags on some NICs.

Two mechanisms exist:

**tc flower with `skip_sw`:**

```
tc filter add dev <outside> ingress protocol ip flower skip_sw \
  dst_ip 192.0.2.10/32 ip_proto udp dst_port 123 action drop
```

- Offloaded drop exists in `mlx5` (NIC mode and switchdev), `ice`, `bnxt_en`
  (when firmware flow offload is present) and `sfc` (driver sources).
- Requires `ethtool -K <outside> hw-tc-offload on`.

**ethtool ntuple, action -1 (discard):**

```
ethtool -N <outside> flow-type udp4 dst-ip 192.0.2.10 dst-port 123 action -1
```

| Driver | Ntuple drop rule capacity |
| --- | --- |
| `mlx5` | 1024 |
| `ice` | up to 16k (firmware-dependent guaranteed pool) |
| `i40e` | firmware-reported |
| `ixgbe` | 2046 |
| `bnxt_en` | supported; capacity not documented |

### Proposed shape

1. **Off by default.** A collector flag `-scrub-hw-predrop`, scrub mode
   only, and only for rules with action `DROP`. Never for `RATE_LIMIT`
   (hardware rate limits are not comparable) or `PASS`.
2. **Software stays authoritative.** Every hardware rule is also installed in
   `xdp_scrub` as today. Hardware is an accelerator only: if a hardware
   install fails or the table is full, the rule still applies in XDP.
3. **Translate only exact equivalents.** A rule whose match cannot be
   expressed exactly stays software-only. This covers source or destination
   port ranges that would expand to more than a few entries, packet length,
   fragment flags, and TCP flag masks the NIC does not support. No widening
   and no approximation, ever: a wider hardware match drops legitimate
   traffic.
4. **Bounded and owned.**
   - A configurable cap, below the NIC's documented capacity.
   - Rules tagged by priority/chain (tc) or location range (ntuple), so the
     collector only touches its own entries.
   - Removal on rule expiry, on `COMMAND_SET_RULES` removal, on collector
     stop and on startup (stale entries from a crash).
5. **Observable.** Hardware rule counters (`tc -s filter show`; ntuple has
   none on most drivers) are exported next to
   `packetyeeter_scrub_rule_matches_total`. Hardware-dropped packets never
   reach XDP, so the XDP counters and fingerprints stop seeing them. The
   controller must read both, or it will think an attack ended
   ([attack end is the controller's call](operations.md#decision-stream-for-controllers)).
6. **Dry-run and monitor mode** install no hardware drops.

### Safety analysis

- **False positives.** The risk is the same as the software rule, provided
  translation is exact. The new risk is NIC-specific match semantics:
  - masks: ixgbe expects inverted masks;
  - flow types: a `udp4` ntuple rule does not match IP fragments without
    ports, while the software rule might.

  Mitigation: a per-driver translation test against the software matcher on
  generated packets, using `BPF_PROG_TEST_RUN` on one side and a NIC loopback
  test on the other.
- **Losing visibility.** Fingerprints and per-source rate state no longer see
  dropped traffic. This is acceptable for confirmed attack signatures, and is
  why the feature is DROP-only and opt-in.
- **Firmware and driver bugs.** Offload behaviour varies by firmware version.
  Side effects to watch:
  - turning `ntuple` off flushes every rule;
  - changing a flow type's input set requires removing all its rules;
  - Intel aRFS/ATR share the Flow Director.

  Gate per driver, and refuse to enable when `hw-tc-offload`/`ntuple` cannot
  be set without changing other offloads.
- **Stale rules after a crash.** A killed collector leaves hardware drops in
  place, unlike XDP, which detaches with the process. The startup cleanup and
  a documented `tc filter del dev <outside> ingress pref <n>` recovery cover
  this. It is the strongest argument for keeping the feature opt-in.
- **Capacity exhaustion during an attack.** Fall back to software for the
  overflow, smallest-prefix-first or by priority, and count it.

## Sources

Tags: [I] independent measurement, [V] vendor (the NIC maker on its own
driver), [K] kernel source or docs.

1. [I] Høiland-Jørgensen et al., "The eXpress Data Path", CoNEXT 2018.
   ConnectX-5, Xeon E5-1650 v4: 24 Mpps/core drop, 115 Mpps max, PCIe limit
   70 Mpps for same-NIC forwarding.
   <https://github.com/xdp-project/xdp-paper/blob/master/xdp-paper.tex>
2. [I] xdp-paper benchmark data:
   - bench05, `XDP_REDIRECT` via devmap: 8.65 Mpps/core; 6 cores 29.8 → 46.1 Mpps with 1024 → 256 RX ring.
   - bench04, `xdp_fwd`: 5.2–5.4 Mpps/core, 3.45 with a full BGP table.

   <https://github.com/xdp-project/xdp-paper/blob/master/benchmarks/bench05_xdp_redirect.org>,
   <https://github.com/xdp-project/xdp-paper/blob/master/benchmarks/bench04_fwd.org>
3. [I/K] Merge ba92660362ec (Linux 5.6): devmap redirect 8.4 Mpps on 1 CPU,
   bulking for `bpf_redirect(ifindex)`.
   <https://github.com/torvalds/linux/commit/ba92660362ec>
4. [V] mlx5 commit 58b99ee3e3eb (Linux 4.19): redirect_map 7 Mpps on one
   queue at 2.5 GHz. <https://github.com/torvalds/linux/commit/58b99ee3e3eb>
5. [V] mlx5 commit b66b76a82c88 (Linux 6.16): ConnectX-6 Dx `XDP_DROP` 31.5–32.3 Mpps, 1 channel.
   <https://github.com/torvalds/linux/commit/b66b76a82c88>
6. [I] S. Miano, netdev regression report, June 2024: ConnectX-6 Dx `XDP_DROP` 30 Mpps (5.15) vs
   20–22 Mpps (6.2–6.10). Quoted from search snippets; the archive was
   unreachable. <https://lore.kernel.ime.usp.br/netdev/87wmmkn3mq.fsf@toke.dk/>
7. [I] Cloudflare, "How to drop 10 million packets per second": 10.1 Mpps
   `XDP_DROP` per core on 10 GbE Intel, 4.14 with KPTI/retpoline.
   <https://blog.cloudflare.com/how-to-drop-10-million-packets/>
8. [I] Brouer, commit 735fc4054b3a (Linux 4.18): bulked `ndo_xdp_xmit`,
   ixgbe 6.85 and i40e 6.72 Mpps redirect.
   <https://github.com/torvalds/linux/commit/735fc4054b3a>
9. [I] Brouer, generic vs native XDP on mlx5: 8.15 vs 19.8 Mpps drop.
   <https://prototype-kernel.readthedocs.io/en/latest/blogposts/xdp25_eval_generic_xdp_tx.html>
10. [V] mlx5 commit 22f453988194 (Linux 4.17): striding RQ `XDP_DROP`
    126 Mpps at 64 bytes, 24 rings. <https://github.com/torvalds/linux/commit/22f453988194>
11. [K] XDP RX metadata kfuncs and netdev netlink spec.
    <https://docs.kernel.org/networking/xdp-rx-metadata.html>,
    <https://docs.kernel.org/netlink/specs/netdev.html>
12. [K] NAPI, busy polling and threaded NAPI.
    <https://docs.kernel.org/networking/napi.html>
13. [K] Intel driver documentation (XDP frame size, Flow Director caveats).
    <https://docs.kernel.org/networking/device_drivers/ethernet/intel/ice.html>,
    <https://docs.kernel.org/networking/device_drivers/ethernet/intel/i40e.html>,
    <https://docs.kernel.org/networking/device_drivers/ethernet/intel/ixgbe.html>
14. [I] Brouer, "XDP – DDoS protecting", LLC 2017.
    <https://people.netfilter.org/hawk/presentations/LLC2017/XDP_DDoS_protecting_LLC2017.pdf>
15. [K] Driver capability matrix: `xdp_features` and `xdp_metadata_ops` in
    each driver under <https://github.com/torvalds/linux/tree/master/drivers/net>,
    and `__xdp_enqueue` in <https://github.com/torvalds/linux/blob/master/kernel/bpf/devmap.c>.
