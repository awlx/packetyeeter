# Operations Guide

Use this checklist when deploying PacketYeeter into production-like environments.

## Deployment sequence

1. Build and deploy the analyzer first.
2. Start the analyzer with `-dry-run` so detections update logs and metrics without sending BLOCK commands.
3. Deploy one collector on a canary host with conservative thresholds and explicit allowlists for trusted networks.
4. Review structured logs, Prometheus metrics, and `yeetctl list`.
5. Tune thresholds and allowlists, then expand to a small host batch.
6. Disable dry-run only after canary behavior is understood.

## Listener exposure

Default listeners are convenient for labs but should be deliberately bound in production.

| Component | Listener | Default | Guidance |
| :--- | :--- | :--- | :--- |
| Analyzer gRPC | `-listen-addr` | `0.0.0.0:9090` | Plaintext and unauthenticated by default: anyone who can reach it can stream signals and, with `-enable-rule-api` or `-enable-watch-api`, push rules or read the decision stream. Turn on [mTLS](#tls-and-mtls), restrict the control-plane RPCs with `-control-client-names`, and firewall it to collectors and controllers. |
| Analyzer metrics | `-metrics-addr` | `:9091` | Bind to loopback/management networks or restrict with firewall/VPN. |
| Analyzer inspector | `-inspect-addr` | `127.0.0.1:9092` | Keep loopback unless placed behind trusted access controls. State-mutating routes are protected by a same-origin/DNS-rebinding guard; behind a reverse proxy, add the proxy hostname to `-inspect-trusted-hosts` so mutating requests are accepted. Read-only GETs are never gated. |
| Analyzer pprof | `-pprof-addr` | `:6060` when enabled | Enable only temporarily for diagnostics and bind securely. |
| Collector metrics | `-metrics-addr` | `:2112` | Scrape from Prometheus over a trusted network. |
| Collector management | `-socket` | `/var/run/packetyeeter-collector.sock` | Created with mode `0600` (owner-only); run `yeetctl` as the same user or relax with a group and chmod after start. |
| HAProxy SPOE | `-spoe-port` | `9876` | Expose only to the local HAProxy instance. |

## TLS and mTLS

The analyzer gRPC listener and the collector's connection to it are plaintext
by default, so existing deployments keep working. Plaintext is acceptable only
on a trusted, isolated network: without TLS, signals and block commands can be
read and forged by anyone on the path, and anyone who can reach the listener
can act as a collector.

| Mode | Analyzer | Collector |
| :--- | :--- | :--- |
| Plaintext (default) | no TLS flags | no TLS flags |
| TLS: collectors verify the analyzer | `-tls-cert`, `-tls-key` | `-analyzer-tls-ca` |
| mTLS: both sides verify each other | add `-tls-client-ca` | add `-analyzer-tls-cert`, `-analyzer-tls-key` |

Use mTLS in production. TLS alone encrypts traffic and authenticates the
analyzer, but still lets any client connect. TLS 1.2 is the minimum; Go's
default cipher suites are used and TLS 1.3 is preferred when both sides support
it. Inconsistent flags (a certificate without its key, `-tls-client-ca`
without `-tls-cert`, client flags without `-analyzer-tls-ca`, unreadable or
unparsable files) stop the process at startup.

### Creating a CA and certificates

A private CA dedicated to PacketYeeter keeps the trust decision narrow: any
certificate it signs can connect. Keep its key offline.

```bash
# CA (keep ca.key offline)
openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout ca.key -out ca.crt -days 3650 -subj "/CN=PacketYeeter CA"

# Analyzer: the SAN must match what collectors dial (-analyzer-addr host) or
# -analyzer-tls-server-name. IP literals need an IP SAN.
openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout analyzer.key -out analyzer.csr -subj "/CN=analyzer.example.net"
openssl x509 -req -in analyzer.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out analyzer.crt -days 365 \
  -extfile <(printf 'subjectAltName=DNS:analyzer.example.net,IP:10.0.0.5\nextendedKeyUsage=serverAuth')

# One client certificate per collector, and one per controller.
for name in collector-web01 controller.example.net; do
  openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$name.key" -out "$name.csr" -subj "/CN=$name"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$name.crt" -days 365 \
    -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=clientAuth' "$name")
done
```

Certificate requirements:

- The analyzer certificate needs a SAN for every name or IP collectors dial;
  the CommonName is ignored for server verification. Use
  `-analyzer-tls-server-name` when collectors dial an address that is not in
  the SAN list (for example an IP behind a load balancer).
- Server certificates need `extendedKeyUsage=serverAuth`, client certificates
  `clientAuth`.
- Client certificates are identified by DNS SAN or CommonName for
  `-control-client-names`; give each controller a distinct name.

```bash
# Analyzer
packetyeeter-analyzer -tls-cert /etc/packetyeeter/tls/analyzer.crt \
  -tls-key /etc/packetyeeter/tls/analyzer.key \
  -tls-client-ca /etc/packetyeeter/tls/ca.crt \
  -control-client-names controller.example.net

# Collector
packetyeeter-collector -analyzer-addr analyzer.example.net:9090 \
  -analyzer-tls-ca /etc/packetyeeter/tls/ca.crt \
  -analyzer-tls-cert /etc/packetyeeter/tls/collector-web01.crt \
  -analyzer-tls-key /etc/packetyeeter/tls/collector-web01.key
```

Keys must be readable by the service user only (`chmod 0600`, owned by the
service user). The analyzer unit's `ProtectSystem=strict` still allows reading
`/etc`.

### Rollout

1. Issue certificates and enable `-tls-cert`/`-tls-key` on the analyzer.
   Plaintext collectors cannot connect from this point, so move collectors in
   the same change window, or run a second analyzer on another port.
2. Add `-analyzer-tls-ca` to collectors; check the collector log line
   `Connecting to analyzer...` shows `tls=true` and the stream stays up.
3. Add client certificates to every collector, then `-tls-client-ca` on the
   analyzer. Clients without a valid certificate fail the TLS handshake.
4. Optionally add `-control-client-names`.

### Rotation

Certificates, keys and CA bundles are re-read without a restart: before each
new TLS handshake the file's modification time and size are checked, and the
file is parsed again when they changed. Existing connections keep the
certificate they were established with; collectors pick up a new analyzer
certificate when they reconnect.

- Replace files atomically (write to a temporary file in the same directory,
  then `mv`). A certificate and key that do not match yet, or a file that does
  not parse, is logged once per change as `Cannot reload ...` and the
  previously loaded material stays in use. Nothing crashes, so watch for that
  log line after rotating.
- To rotate the CA, first append the new CA to every CA bundle
  (`-tls-client-ca`, `-analyzer-tls-ca`), then issue new certificates, then
  remove the old CA.
- The analyzer does not check revocation lists. To cut off a compromised
  client certificate, rotate to a new CA or remove its name from
  `-control-client-names`.

### Control-plane authorization

With `-control-client-names` set, only clients whose verified certificate has
a matching DNS SAN (case-insensitive) or CommonName (exact) may call
`PushRules` and `WatchDecisions`; others get `PermissionDenied` and the
analyzer logs `Denied control-plane RPC`. `StreamSignals` and the lookup RPCs
stay available to every client with a valid certificate, so collectors need no
special names. Without it, any client trusted by `-tls-client-ca` can use the
control-plane RPCs. Because a collector certificate can then push rules for
the whole fleet, set `-control-client-names` whenever collectors run on hosts
you trust less than your controller.

## systemd hardening notes

The analyzer is userspace-only and can run with normal hardening such as `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, and a narrow `ReadWritePaths=/var/lib/packetyeeter`.

The collector is intentionally less restricted because it loads eBPF, attaches XDP/TC programs, opens raw/network resources, and uses pinned kernel maps. It needs BPF/network capabilities and `LimitMEMLOCK=infinity`. Avoid adding hardening directives that hide devices, remove BPF capabilities, block network address families, or prevent kernel map/program access unless validated on the target kernel.

## Staged tuning

- Begin with analyzer `-dry-run`.
- Keep `-enable-high-cardinality-metrics=false` during normal operations; turn it on only for short diagnostic windows.
- Set allowlists for monitoring systems, load balancers, bastion hosts, health checks, and upstream trusted proxies.
- Watch `packetyeeter_*_blocks_total`, reputation scores, AI detections, SPOE queue depth/drops, and collector/analyzer logs before enabling enforcement.
- Per-IP and per-JA4 reputation penalties accumulate. Analyzer defaults apply
  finite score caps (`-reputation-ip-score-cap=200`,
  `-reputation-ja4-score-cap=200`, `-reputation-asn-score-cap=500`; `0` =
  uncapped) so scores can still clear the ban threshold with headroom but cannot
  run away indefinitely. Re-baseline in `-dry-run`, review reputation scores and
  `packetyeeter_*_blocks_total`, and tune allowlists/thresholds/caps before
  enabling enforcement.
- Collector `-udp-frag-mode` defaults to `rate` (rate-limit fragmented UDP / IPv6
  fragments instead of hard-dropping them). Use `drop` only when restoring the
  legacy unconditional drop is intentional.
- Treat UDP reflection campaign labels as observability metadata. The analyzer can distinguish common vectors such as DNS, NTP, SSDP, CLDAP, Memcached, and QUIC Initial only when existing signal metadata carries useful port or protocol hints; ambiguous UDP campaigns remain labeled `udp_flood`.
- Treat adaptive campaign baselines as rollout context, not enforcement. During analyzer startup or a new service/vector mix, `baseline_enough_samples=false` means the EWMA is still warming up; compare `baseline_current_rate`, `baseline_rate`, and `baseline_multiplier` only after enough samples have accumulated for that service key.
- The adaptive baseline caps how fast it can rise per observation (`MaxGrowthPerObservation`, default 1.5x) to resist slow-ramp attacks that try to normalize themselves into the baseline; if legitimate traffic grows unusually fast, the baseline may lag for a few observation cycles before catching up. See `docs/observability.md` for details and tuning guidance.
- Campaign/carpet-bombing detections are observe-only: they do not mutate
  reputation for a representative sample IP/ASN. Use campaign metrics and
  inspector views for tuning; do not expect campaign membership alone to raise
  ban scores.
- On dual-stack hosts, the collector now emits IPv6 ICMP/UDP flood and
  incomplete-handshake signals (previously IPv4-only). Expect new IPv6
  detections after upgrading; stage with analyzer `-dry-run` and verify IPv6
  allowlists (health checks, monitoring, upstream proxies) before enforcing.
- Roll back by re-enabling dry-run or stopping collectors before changing eBPF-related systemd hardening.

## Sustained-download detection rollout

Sustained-download detection selects on duration and breadth rather than rate,
so its thresholds cannot be inherited from rate-limit tuning. It ships disabled,
and enabling detection does not enable blocking.

1. Enable the collector inputs. Set `-egress-accounting` on one collector and
   confirm `packetyeeter_egress_volume_signals_total` and
   `packetyeeter_egress_bytes_reported_total` are advancing. Without this only
   the breadth/shape path can ever fire: HAProxy cannot report transferred bytes
   over SPOE, so eBPF TC egress counters are the only byte source.
   Raise `-egress-min-bytes` if the signal stream is noisier than expected.
2. Enable detection only. Start the analyzer with `-sustained-enabled` and
   without `-sustained-enforce`. Every decision is logged as
   "detect-only, not blocking" and counted under
   `packetyeeter_sustained_decisions_total{outcome="would_block"}`.
3. Tune from the inspector, not from guesswork. `GET /api/sustained` reports,
   per client, which thresholds it is under (`blockers`) and how close it is to
   each (`margins`, as a percentage). Sort with `?by=bytes|requests|resources|sections`.
   Clients sitting at 90-100% on every margin are the ones the thresholds are
   about to catch; review those before enforcing.
   - Note the two paths are independent. `path: "shape"` means breadth with no
     byte floor at all, which is the enumeration case; `path: "volume"` means
     bulk transfer. If ordinary deep usage (a CI job, a package mirror client)
     is landing in the shape path, lower
     `-sustained-max-resources-per-section-percent` rather than raising the
     resource minimum.
4. Watch capacity. A growing `packetyeeter_sustained_client_evictions_total`
   means more clients share the window than `-sustained-max-clients` allows, so
   detection is being applied to an arbitrary subset. Raise the ceiling before
   trusting the results.
5. Enforce on one analyzer. Add `-sustained-enforce`. Expect
   `packetyeeter_sustained_held_clients` to become nonzero and stay there:
   blocking removes the byte evidence that selected the client, so the hold is
   what keeps the block in place. A hold that never drains means blocked clients
   are not backing off; `-sustained-max-hold-seconds` bounds it regardless.
6. Keep the analyzer-wide kill switch reachable (see below). It is not specific
   to this detector, which is the point: if traffic is being blocked that should
   not be, stopping it should not require identifying the responsible detector
   first.

Allowlisted IPs are skipped entirely. Verified crawlers are not - they get their
request and byte floors multiplied by `-sustained-reputation-factor`, so a
verified crawler that starts mirroring the site is still caught. If a verified
crawler is being caught legitimately, allowlist it rather than raising the
factor for everyone.

## Bot verification

Requests whose User-Agent claims a DNS-verifiable crawler (Googlebot, Bingbot,
Baiduspider, YandexBot, facebookexternalhit, Twitterbot, Slackbot) are checked
with reverse and forward-confirming DNS. The verdict is cached per IP (1 hour;
transient DNS failures 1 minute).

The lookups run on a bounded worker pool (16 workers, 1024 queued lookups), not
on the collector's signal stream: a PTR server that never answers can no longer
stall signal processing. In-flight lookups are de-duplicated per IP. The DNS
budget is unchanged (5 seconds for reverse plus forward together), and
in-flight lookups are cancelled on analyzer shutdown.

Until an IP has a cached verdict, its requests are handled as follows:

- **Pending** (lookup queued or running, for at most the 5-second DNS
  budget since it was queued): the request is unverified. It gets
  neither the verified-bot exemption (no positive signal, no raised
  sustained-download floors) nor the impersonation penalty. Heuristics that
  presume a browser UA claim is false (header order, `sec-ch`, `Sec-Fetch-*`,
  `Accept`, TLS version, JA4 rotation) are skipped, because a verified crawler
  would be exempt from them. Everything else - rate limits, error tracking,
  JA4DB, bot-keyword and missing-header signals, threat intel and the
  reputation threshold - applies as for any unverified client.
- **Dropped** (queue full, or the verdict cache is full): no lookup is started
  and the request is handled as a plain unverified client, with all
  heuristics. Treating it as pending would let a lookup flood switch those
  heuristics off. The same applies once a lookup has been queued or running
  for longer than the DNS budget, so a backlog cannot stretch the pending
  window.

Requests after the lookup completes get the cached verdict: verified bots are
exempt, impersonators are penalised. In practice the first request or few from
a new crawler IP are unverified rather than verified or penalised. This errs
towards neither blocking nor allowlisting on an unconfirmed claim.

Watch `packetyeeter_bot_verification_queue_depth` and
`packetyeeter_bot_verification_queue_drops_total`. Sustained drops mean
lookups are slow or a flood of new bot-claiming IPs is arriving; check
resolver latency before anything else.

## Runtime enforcement kill switch

`POST /api/enforcement/stop` on the analyzer's inspector suppresses every
enforcing command the analyzer would issue - from all detectors - while leaving
detection, scoring, metrics, and the reporting surfaces running.

```bash
curl -sS -X POST http://127.0.0.1:9092/api/enforcement/stop \
  -H 'Content-Type: application/json' \
  -d '{"reason":"INC-1234 blocking legitimate CI traffic"}'

curl -sS http://127.0.0.1:9092/api/enforcement
```

- It complements `-dry-run` rather than duplicating it. `-dry-run` is a
  deployment decision fixed at startup; this is an incident response reachable
  in seconds, without a restart and without editing a unit file.
- Relieving commands - unblock and allowlist - keep flowing. The switch is
  pulled precisely when a block is wrong, so suppressing the commands that undo
  a block would make the incident worse.
- It is one-way. Resuming enforcement requires a config change and a restart,
  which leaves a record of the decision. The state is not persisted, so a
  restart returns to whatever the deployed configuration says - if you stopped
  enforcement because a threshold is wrong, fix the threshold before restarting.
- It is same-origin guarded like every other mutating inspector endpoint, so the
  inspector must stay on loopback or behind trusted access controls (see
  "Listener exposure").
- Alert on `packetyeeter_enforcement_stopped == 1`. Because it survives until a
  restart, an unnoticed kill switch means the fleet has been silently
  detect-only, possibly for days. `packetyeeter_enforcement_suppressed_commands_total`
  shows how much enforcement is being withheld.

## Scrub mode

`-mode scrub` turns a Linux server into an inline scrubber. Edge routers send
traffic for an attacked address to the node's outside port (`-i`); `xdp_scrub`
drops attack traffic with the same checks as host mode (blocked IPs, `-policy`,
bad TCP flags, fragment policy, ICMP/UDP rate limits) and forwards the rest out
of the inside port (`-inside-if`) at XDP speed. Replies take the normal path
and never cross the node.

```bash
sudo packetyeeter-collector -mode scrub -i eth0 -inside-if eth1 -dry-run
```

Requirements, checked at start-up (the collector refuses to start otherwise):

- Linux 5.15 or newer, and native XDP on both ports (`-allow-generic` for labs).
  At start-up the collector logs one `Scrub port attached` line per port, with
  its XDP mode and driver XDP features (Linux 6.3+). It warns if the outside
  driver lacks `XDP_REDIRECT`, or if the inside driver lacks `ndo_xdp_xmit`,
  which makes the kernel drop every forwarded frame. With `-allow-generic`, a
  generic inside port forces the outside port to generic too.
  `yeetctl nic-check` runs the same checks before deployment;
  [scrub-hardware.md](scrub-hardware.md) covers NIC choice and tuning.
- `net.ipv4.ip_forward=1` and `net.ipv4.conf.<outside>.forwarding=1`, plus
  `net.ipv6.conf.all.forwarding=1` and `net.ipv6.conf.<outside>.forwarding=1`
  when the node has a global IPv6 address on either port or any IPv6 route
  (other than link-local/multicast) out of the inside port, e.g. a route via a
  link-local next hop. The kernel forwards whatever XDP cannot (no neighbour
  entry yet, TTL expiry, MTU, VLAN-tagged frames) and keeps forwarding if the
  collector stops. `bpf_fib_lookup` checks the outside port's own setting, so
  the per-port sysctls matter even with the global one set.
- `rp_filter` 0 or 2 on the outside port: attack sources are spoofed, and strict
  mode drops them in the kernel path.

Routing:

- Protected prefixes must be routed via the inside port only.
- The inside network must not learn the redirect route, or forwarded traffic
  loops back to the edge; `packetyeeter_scrub_ttl_expired_total` rising is the
  symptom.
- Multicast and link-local destinations, ARP and IPv6 neighbour discovery
  always reach the local stack unchecked, so routing protocols and neighbour
  resolution keep working.
- Unicast traffic to the node's own addresses (BGP and management addresses,
  VIPs on `lo`, port addresses) is checked against `blocked_ips` and `-policy`
  (honouring the allowlist and monitor mode) and otherwise passed to the local
  stack. The bad-flags, fragment and ICMP/UDP rate-limit checks are not
  applied: they are sized for forwarded traffic and would throttle the node's
  control plane. Up to 4096 addresses per family are tracked; start-up fails if
  the node has more, and later overflows are logged once until they clear.

Readiness and failure:

- `GET /readyz` on `-metrics-addr` returns 200 only while `xdp_scrub` is
  attached, the inside port is up and a redirect target, and forwarding is
  enabled; otherwise 503 with the reason. Use it to decide whether the node may
  be a next hop.
- On SIGTERM the node reports 503 for `-readyz-drain` before detaching, so
  traffic can move away first. The control plane (analyzer block commands,
  block expiry, `local_addrs` sync, incident reporting) keeps running during the
  drain; `xdp_scrub` is detached before `xdp_pass_inside` so in-flight
  redirects are not dropped.
- If the collector crashes, the kernel detaches XDP and keeps forwarding
  unscrubbed traffic: the node fails open, never blackholes.

Slow-path limit: packets that need the kernel (TTL <= 1, oversize with DF,
destinations without a neighbour entry, routes out of other ports, forwarding
disabled) are capped at `-scrub-slow-path-pps` (default 100000, 0 = unlimited)
across all CPUs, so floods aimed at the slow path cannot exhaust the kernel or
its neighbour table (a random-destination flood into a connected IPv6 /64).
The budget is split evenly over CPUs, so traffic concentrated on one RX queue
hits its share sooner. The tradeoff: while the cap is reached, legitimate
slow-path packets are dropped too, which delays neighbour resolution for new
destinations and suppresses ICMP errors (time exceeded, packet too big) until
the next second. VLAN-tagged traffic, which always takes the slow path, is not
counted. Watch `packetyeeter_scrub_slow_path_limited_total`; in `-dry-run`
over-limit packets are passed and only counted. Size the cap above the normal
slow-path rate (`rate(packetyeeter_scrub_packets_total{verdict="slow_path"})`).

Rollout: start with `-dry-run` (drops are logged as incidents and forwarded),
compare `packetyeeter_kernel_incidents_total` with expected attack traffic,
then remove `-dry-run`. Scrub nodes do not run SPOE, JA4H or egress accounting.

Incomplete-handshake signals work on scrub nodes too, tracked in XDP: replies
bypass the node, so a handshake counts as complete when the client's first ACK
arrives rather than after the server's SYN-ACK. Only SYNs the node actually
forwarded in XDP are tracked; any ACK without SYN or RST on the same 4-tuple
closes the entry, even one the kernel forwards. The node cannot check that ACK
against the server's sequence number, so a sender that follows each SYN with a
blind ACK avoids these signals; the per-source rate limits and blocks still
apply. Signals reach the analyzer after
`-handshake-timeout` (default `3s`) and use the same `-ddos-min-incomplete`
threshold as host mode. Handshake RTT (JA4L) needs the SYN-ACK and is not
available in scrub mode.

Scrub nodes keep these entries in `scrub_handshakes(_v6)` (500k entries per
family; `bpftool` truncates both names to `scrub_handshake`) with per-CPU LRU
lists. The kernel gives every possible CPU (`/sys/devices/system/cpu/possible`)
an equal share, and under a random-source SYN flood each CPU evicts its own
oldest entries: a CPU taking most of the flood, or a host with far fewer online
than possible CPUs, evicts sooner than the total size suggests. A SYN evicted
before its ACK is never reported.

A connection's SYN and first ACK must cross the same scrub node. With several
nodes, keep ECMP hashing on the 5-tuple, and expect a short burst of
incomplete-handshake signals whenever flows move: a node draining or joining,
or the redirect being withdrawn. A SYN lost between the node and the victim is
retransmitted after about 1s and again after 3s, so on a congested victim link
some legitimate clients exceed the default timeout; raise
`-handshake-timeout` if that shows up as false positives.

Labs on veth pairs: the veth receiving redirected frames needs GRO enabled
(`ethtool -K <peer> gro on`) on its peer, and locally generated test traffic
needs tx checksum offload disabled on the sender. `make e2e-scrub-test` sets
this up.

Throughput: measure on the target hardware before relying on a node; see
[docs/scrub-throughput.md](scrub-throughput.md) for the procedure and the veth
reference numbers (`make bench-scrub-veth`).

### Runtime rules

A controller pushes rules with the analyzer's `PushRules(RuleSet)` RPC, which
is refused unless the analyzer runs with `-enable-rule-api`. Each `RuleSet`
is the complete set for one `scope` (a controller identity); pushing an empty
set removes the scope's rules, and scopes never overwrite each other (rule
ids are sent as `<scope>/<id>`). The analyzer validates the set, checks that
all scopes together still fit the limits below, and sends every scrub
collector the complete set of all scopes as a replacement
(`COMMAND_SET_RULES` with `RuleSetDelta.replace`). It does this on every push,
when a collector (re)connects and once a minute, because collectors do not
acknowledge rules: a collector that rejected or missed a set converges within
a minute, and rules a restarted analyzer no longer knows are removed.
`PushRulesAck.collectors` says how many scrub collectors were sent the set
within 10 seconds; it does not confirm they applied it, so compare
`packetyeeter_scrub_rules_active` on the collectors. All scopes together must
also encode to at most 3 MiB. A rule is withdrawn from collectors 5 seconds
before its `expires_at`, so a collector whose clock runs slightly ahead does
not reject the whole set.

Rules live in the analyzer's memory: after a restart it would send scrub
collectors an empty set, clearing their rules until the controller pushes
again. With `-rule-state-dir DIR` the analyzer writes every accepted push to
`DIR/scrub-rules.json` (mode 0600, written atomically) and restores the
unexpired rules on start, before collectors connect. Restored rules are
checked like pushed ones; invalid or expired entries are skipped. A file that
cannot be read as rule state is renamed to `scrub-rules.json.corrupt-<time>`
and the analyzer starts without rules. Failures are logged and counted in
`packetyeeter_rule_state_errors_total{op}`. The file is as sensitive as the
rule API itself: keep the directory writable by the analyzer only.

While the analyzer is not enforcing (`-dry-run`, or the runtime kill switch),
only `PASS` rules are sent, and pulling the kill switch withdraws the `DROP`
and `RATE_LIMIT` rules collectors already hold.

The gRPC listener is unauthenticated unless mTLS (`-tls-client-ca`) is
configured: without it, anyone who can reach `-listen-addr` can push rules
once the API is enabled, and any client that announces itself as a scrub
collector receives them. Run the analyzer with mTLS and restrict `PushRules`
with `-control-client-names` (see [TLS and mTLS](#tls-and-mtls) and
[control-plane authorization](#control-plane-authorization)), or firewall the
listener to the controllers and collectors.

Scrub collectors announce their role when they connect; an analyzer older than
this release ignores the announcement, since it carries no IP. A rule matches
traffic for its `dst_prefix` on any combination of protocols, source and
destination port ranges, IP total length, TCP flags (`flags & mask ==
value`), fragment state and up to 8 source prefixes, and then:

- `DROP` drops the packet (logged as incident `rule_match`);
- `RATE_LIMIT` drops what exceeds `rate_pps` (one budget per rule shared by
  all CPUs; 100ms windows, 1s below 100 pps);
- `PASS` forwards it without the per-source checks (blocked IPs, `-policy`,
  rate limits, bad TCP flags).

Rules run after the allowlist and before the per-source checks; the first
matching rule by `priority` (lower first, ties by `id`) decides, whatever the
prefix lengths. `-dry-run` counts and logs rule drops but forwards. A
per-source `-policy` `monitor` entry does not exempt a source from rules; the
allowlist does. Traffic to the node's own, multicast and link-local addresses
is never matched against rules.

Limits: 4096 rules per address family, 8 port ranges per direction, 8 source
prefixes, and 32 rules covering any one destination. A delta that breaks a
limit, or contains any invalid rule, is rejected whole and logged; the
previous rules stay active. `expires_at` is required; expired rules are removed
within a second. Rules live in memory only: after a collector restart they are
back once the analyzer resends them.

### Decision stream for controllers

`WatchDecisions` is a server stream on the analyzer's gRPC listener for a
controller that steers traffic to scrub nodes. It is off unless the analyzer
runs with `-enable-watch-api`; otherwise calls fail with `PERMISSION_DENIED`.
At most `-watch-max-subscribers` (16) streams are served at once; more fail
with `RESOURCE_EXHAUSTED`.

Each `Decision` is one of:

- `command`: every `Command` the analyzer sends to collectors, once per
  decision however many collectors receive it. Only commands that are actually
  sent are published: commands suppressed by `-dry-run`, by the enforcement
  kill switch, or as a duplicate block within the dedup window are not, so the
  stream reflects enforcement. With `-dry-run` the stream carries no blocks.
  Today the analyzer issues `BLOCK_IP` (not `BLOCK_CIDR`), unblock and
  allowlist commands.
- `campaign`: each campaign observation the campaign engine logs as
  `attack_campaign_observed`. `vector` and `observed_at` are always set.
  `protocol` (IP protocol number) and `dst_port_bucket` come from the
  campaign baseline and are `0`/empty when unknown; `dst_prefix` is the
  destination /24 (IPv4) or /64 (IPv6) for a single-subnet campaign and
  empty for cross-subnet and cross-collector rollups; `rate_pps` is the
  campaign's signal rate over its window, not a packet rate.
- `fingerprint`: each `SIGNAL_SCRUB_FINGERPRINT` from a scrub collector,
  passed through unchanged. Fingerprints are never scored and never touch
  reputation, also when the stream is disabled. `collector_id` is always
  replaced with the analyzer's id for the collector stream (`peer#n`), since
  the field is set by the client. Malformed fingerprints (`dst_ip` and
  `src_net` not both 4 or both 16 bytes, buckets, protocol or port out of
  range, `interval_seconds` outside 1-3600) are dropped and counted in
  `packetyeeter_watch_invalid_fingerprints_total`.

Buffering and ordering: each subscriber has its own buffer of
`-watch-buffer-size` (10000) decisions. Publishing never waits for a
subscriber, so a slow controller cannot slow signal processing or command
delivery. When a subscriber's buffer is full, its oldest decision is dropped
and counted in `packetyeeter_watch_dropped_total`; other subscribers are
unaffected. Each subscriber receives decisions in publish order, and all
subscribers see the same order. There is no replay: a controller sees only
what is published while it is connected, and on reconnect should rebuild its
view from new decisions.

The analyzer has no notion of a campaign ending. Withdrawing diversion is the
controller's decision, for example once fingerprint and decision rates for a
destination have stayed low for a while.

Security: the stream exposes attacker and target addresses and enforcement
decisions, and the gRPC listener is unauthenticated unless mTLS
(`-tls-client-ca`) is configured. Run the analyzer with mTLS and restrict
`WatchDecisions` with `-control-client-names` (see [TLS and mTLS](#tls-and-mtls)
and [control-plane authorization](#control-plane-authorization)), or enable it
only when `-listen-addr` is reachable from trusted networks alone.

### Fingerprints

Scrub collectors summarise what they see per destination so a controller can
build edge filters. Every packet that reaches a verdict for redirected
traffic (forwarded, handed to the kernel, or dropped by a rule or per-source
check) is counted in XDP into a bucket keyed by destination address,
protocol, destination port (0 when not TCP/UDP or a later fragment), IP total
length bucket (0: <128, 1: <256, 2: <512, 3: <1024, 4: larger), TTL or hop
limit bucket (TTL / 32), source /24 (IPv4) or /48 (IPv6), and whether it was
dropped. Traffic to the node's own, multicast and link-local addresses, and
frames that cannot be parsed, are not counted. `dropped` is the filtering
verdict: in `-dry-run` nothing is dropped, and slow-path packets over
`-scrub-slow-path-pps` count as not dropped. Bytes are IP total lengths.

Every `-fingerprint-interval` (default `10s`) the collector switches XDP to a
second map, reads and clears the first, and sends the busiest
`-fingerprint-top` (default 32) buckets of each of the 256 busiest
destinations to the analyzer as `SIGNAL_SCRUB_FINGERPRINT`, one signal per
bucket with packets, bytes and the interval length. Fingerprints only enter a
free slot of the signal queue, never displacing detection signals, and are
skipped while the analyzer is disconnected. `-fingerprint-interval 0` turns
fingerprinting off, including the per-packet work in XDP. Both flags only
apply in scrub mode.

Cost: one hash lookup per packet (an insert for a new bucket). The two maps
hold 65,536 buckets each and preallocate their per-CPU counters, about 2 MiB
per CPU in total (nothing with `-fingerprint-interval 0`).

Limitation: with spoofed sources, every random source /24 is a new bucket, so
a flood fills the map within the interval. Further new buckets are then not
counted (`packetyeeter_scrub_fingerprint_overflow_total` rises) while existing
ones keep counting, so the top buckets reflect the traffic shapes seen first in
the interval. The destination and the per-destination totals of sent buckets
remain useful; the source networks do not.

### SYN cookies

Without challenges a scrub node forwards every SYN that passes the per-source
checks, so a spoofed-source SYN flood reaches the server whole: each spoofed
source sends too little to trip a rate limit. `-scrub-syn-cookies` (default
`off`, needs Linux 6.0+) makes the node verify that a source receives packets
sent to its address before forwarding its SYNs.

Replies bypass the node, so it cannot proxy the handshake. Instead, `xdp_scrub`
answers a SYN from an unverified source itself with a SYN-ACK carrying a SYN
cookie (the kernel's, via `bpf_tcp_raw_gen_syncookie_ipv4/ipv6`) and does not
forward it. A spoofed source never sees that SYN-ACK. A real client answers
it; the node checks the cookie, records the source as verified for
`-scrub-syn-cookie-ttl` (default `10m`), and forwards the client's next SYN to
the server as usual. The node keeps no per-connection state, only the
verified sources.

`-scrub-syn-cookie-style` selects how the client answers:

- `oos` (default): the SYN-ACK acknowledges a sequence number the client never
  sent. TCP requires a client in SYN-SENT to answer that with a RST whose
  sequence number is the acknowledgment (RFC 9293, 3.10.7.3) and to keep
  waiting for its own SYN to be answered. The node finds the cookie in that
  RST, verifies the source and drops the RST; the client's SYN retransmission
  then passes. Linux clients retransmit within a few milliseconds of such an
  answer (connect took 4-5 ms instead of under 1 ms in the veth lab); macOS
  and Windows retransmit after their initial SYN timeout, about 1 s (Windows:
  1-3 s depending on version and `InitialRto`). Applications only see a slower
  connect. A stateful firewall in front of the client that drops
  out-of-window SYN-ACKs breaks this: the client never answers and every
  retransmission is challenged again. Linux conntrack (tested on 7.0, also
  with `ct state invalid drop`) lets them through.
- `reset`: the SYN-ACK is valid, so the client completes the handshake and
  its ACK carries the cookie. The server never saw that connection, so the
  node answers the ACK with a RST: the application sees its first connection
  fail (curl: "Couldn't connect to server") and has to reconnect; the
  reconnect passes. Waiting for a SYN retransmission does not work in this
  style, because the client considers itself connected and sends data, which
  the server would reset anyway. Use `reset` only where `oos` challenges get
  lost.

`-scrub-syn-cookies` selects which destinations are challenged:

- `on`: all of them.
- `auto`: a destination receiving more than `-scrub-syn-cookie-syn-pps`
  (default 10000) SYNs per second across all CPUs is challenged for 30 s,
  extended while its rate stays above. As with `-scrub-slow-path-pps`, the
  rate is split evenly over CPUs, so SYNs concentrated on one RX queue reach
  their share sooner; RSS spreads a random-source flood evenly. Destinations
  are hashed into 8192 slots, so an address sharing a slot with an attacked
  one is challenged too. A flood spread thinly over many destinations
  (carpet bombing) may stay below the threshold everywhere: use `on` for such
  prefixes.

What is challenged: plain SYNs to forwarded destinations, after runtime rules
and the per-source checks. Allowlisted sources, sources matched by a `pass`
rule and verified sources are never challenged. While challenges are active,
SYNs the node cannot answer (IPv4 options, IPv6 extension headers,
fragments) are dropped. No other segment is ever dropped by this feature:
connections opened before challenges started keep working. In `oos` style
every RST, in `reset` style every bare ACK, from an unverified source to a
challenged destination is checked for a cookie; those without one are
forwarded.

Client-visible effects and caveats:

- Once per source and TTL, a connect takes one extra round trip plus the
  client's retransmission delay (`oos`), or fails once (`reset`).
- TCP Fast Open: data in a challenged SYN is not delivered; the client sends
  it again after the handshake.
- Sources are verified by address: one verified client verifies its whole
  NAT, and others can spoof a verified address until its TTL expires.
- Challenges leave by XDP_TX: the SYN-ACK goes back out of the outside port
  to the router the SYN came from, sourced from the protected address. The
  edge must accept and route such packets from the scrub node (no uRPF or ACL
  dropping them on that interface).
- With several nodes behind ECMP, a client's answer and retransmitted SYN
  share the 5-tuple of its first SYN and reach the same node; a connection on
  another port may hash to another node and be challenged there again.
- Cookies use the kernel's SYN cookie secret and expire after about two
  minutes. The cookie's low bits encode the MSS, so a few neighbouring values
  are also accepted for the same 4-tuple; guessing one blindly still takes
  millions of tries per 4-tuple.
- Challenged SYNs are not forwarded, so they never open incomplete-handshake
  entries; the flood shows up in `packetyeeter_scrub_syncookie_total` and, as
  drops, in fingerprints.

Cost: SYNs and answer candidates take a few map lookups; a challenge rewrites
the received frame in place. The verified-source maps preallocate 262,144
entries per family (about 42 MiB together), plus 128 KiB per possible CPU for
the auto-mode rates. With `-scrub-syn-cookies off` the verifier removes the
code and the maps shrink to one entry.

Rollout: run `-dry-run -scrub-syn-cookies auto` first. Nothing is answered or
dropped; `packetyeeter_scrub_syncookie_total{event="dry_run"}` shows what
would have been challenged, which helps choose `-scrub-syn-cookie-syn-pps`
above normal peaks. Then enable it on one node.

Labs on veth pairs: a veth only delivers XDP_TX frames promptly when its peer
runs an XDP program; `make e2e-scrub-test` attaches one to the client side.

## Modern DDoS runbook

Use this workflow when campaign metrics or logs indicate a possible L3/L4 DDoS.
Campaign and carpet-bombing detections are observe-only aggregate signals; they
help operators understand blast radius and vector mix, but do not create block
commands on their own.

1. Confirm analyzer health and visibility. Check collector connectivity, signal
   queue pressure, `packetyeeter_active_attack_campaigns`, and recent
   `attack_campaign_observed` logs. If queues are dropping, treat the data as
   incomplete until backpressure is resolved.
2. Identify the dominant vector with
   `sum by (vector) (rate(packetyeeter_attack_campaign_detections_total[5m]))`.
   Interpret specific UDP labels as hints from existing port/protocol metadata:
   `dns_reflection`, `ntp_reflection`, `ssdp_reflection`, `cldap_reflection`,
   `memcached_reflection`, and `quic_initial_flood` are more specific than the
   fallback `udp_flood`.
3. Triage carpet-bombing breadth with
   `packetyeeter_carpet_bombing_detections_total{reason=...}` and the matching
   logs. Destination-subnet breadth usually points to distributed target
   selection; destination-port breadth may indicate service discovery or
   multi-service pressure; source breadth indicates distributed origin volume.
4. Compare the current campaign to adaptive service baselines. Ignore
   `enough_samples="false"` for enforcement decisions because the service key is
   still warming up. Once enough samples exist, use the p95 baseline multiplier
   and `packetyeeter_campaign_baseline_rate` to decide whether the campaign is
   unusual for that protocol/port bucket/vector.
5. Keep enforcement staged. Start or return to analyzer `-dry-run`, add or verify
   allowlists for health checks, trusted proxies, monitoring, and upstream
   providers, then canary enforcement on one collector before widening rollout.
6. Document the vector, affected services, baseline state, actions taken, and
   whether any block commands came from per-source detection paths rather than
   observe-only campaign aggregation.

## Prometheus example

An example scrape configuration is available in [`examples/prometheus-scrape.yml`](../examples/prometheus-scrape.yml). Adjust target hostnames and ports to match your deployment and keep scrape access on a trusted network.

Example alert rules for modern DDoS observations are available in
[`examples/prometheus-alerts.yml`](../examples/prometheus-alerts.yml).
