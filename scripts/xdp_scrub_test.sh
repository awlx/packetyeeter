#!/usr/bin/env bash
# xdp_scrub_test.sh — end-to-end test of collector scrub mode on veth pairs.
#
#   src ns ──veth── scrub ns (collector: -i out -inside-if in) ──veth── dst ns
#
# Requires root, the eBPF toolchain, curl, python3, ethtool and bpftool. Run:
#   sudo ./scripts/xdp_scrub_test.sh
#
# Self-contained: it builds the collector, sets up, tests, and removes only
# the namespaces it created, even on failure.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECTOR_BIN="$REPO/bin/packetyeeter-collector"
TOKEN="$(printf '%04x' $((RANDOM % 65536)))"
NS_SRC="yeetsrc_${TOKEN}"; NS_SCR="yeetscr_${TOKEN}"; NS_DST="yeetdst_${TOKEN}"
CREATED_NS=()
COLLECTOR_PID=""; HTTP_PID=""; SINK_PID=""
SINK_BIN="$REPO/bin/xdp_veth_sink"
SINK_LOG="$(mktemp /tmp/yeet-scrub-sink.XXXXXX.log)"
CMD_FIFO="$(mktemp -u /tmp/yeet-scrub-cmds.XXXXXX)"
COLLECTOR_LOG="$(mktemp /tmp/yeet-scrub-collector.XXXXXX.log)"
UDP_OUT="$(mktemp)"
FAILURES=0

SRC4=10.201.1.2; BLOCKED4=10.201.1.3; POLICY4=10.201.1.4; OUT4=10.201.1.1
IN4=10.201.2.1; DST4=10.201.2.2
SRC6=fd01:1::2; OUT6=fd01:1::1; IN6=fd01:2::1; DST6=fd01:2::2
# Sources whose SYNs go unanswered, and prefixes the destination silently drops
# (routed to it, but it does not forward).
HS4=10.201.1.5; HS6=fd01:1::5; HOLE4=10.201.3.9; HOLE6=fd01:3::9
TTL1_4=10.201.1.6  # its SYNs expire on the scrub node and must not be reported
SLOWACK4=10.201.1.7  # SYN forwarded in XDP, ACK left to the kernel: not reported
RSTACK4=10.201.1.8   # SYN then RST|ACK, which does not complete a handshake
SLOWACK6=fd01:1::7; RSTACK6=fd01:1::8

log()  { printf '\033[1;36m[test]\033[0m %s\n' "$*"; }
pass() { printf '\033[1;32m[pass]\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*"; exit 1; }

cleanup() {
  [[ -n "$COLLECTOR_PID" ]] && kill -9 "$COLLECTOR_PID" 2>/dev/null || true
  [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" 2>/dev/null || true
  [[ -n "$SINK_PID" ]] && kill "$SINK_PID" 2>/dev/null || true
  for ns in "${CREATED_NS[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -f "$UDP_OUT" "$CMD_FIFO"
  log "cleaned up (collector log: $COLLECTOR_LOG, analyzer sink log: $SINK_LOG)"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || die "must run as root: sudo $0"
for t in clang go curl python3 ethtool bpftool ip; do
  command -v "$t" >/dev/null || die "missing $t (Debian/Ubuntu: apt install clang llvm libbpf-dev linux-tools-generic curl python3 ethtool)"
done
for ns in "$NS_SRC" "$NS_SCR" "$NS_DST"; do
  ! ip netns list | awk '{print $1}' | grep -qx "$ns" || die "netns $ns already exists; re-run"
done

log "building eBPF object and collector"
make -C "$REPO" bpf >/dev/null
mkdir -p "$REPO/bin"
( cd "$REPO" && go build -o "$COLLECTOR_BIN" ./cmd/collector && go build -o "$SINK_BIN" ./scripts/xdp_veth_sink )

src() { ip netns exec "$NS_SRC" "$@"; }
scr() { ip netns exec "$NS_SCR" "$@"; }
dst() { ip netns exec "$NS_DST" "$@"; }

log "creating namespaces $NS_SRC, $NS_SCR, $NS_DST"
for ns in "$NS_SRC" "$NS_SCR" "$NS_DST"; do ip netns add "$ns"; CREATED_NS+=("$ns"); done
ip link add src0 netns "$NS_SRC" type veth peer name out0 netns "$NS_SCR"
ip link add in0 netns "$NS_SCR" type veth peer name dst0 netns "$NS_DST"

src ip addr add "$SRC4/24" dev src0
src ip addr add "$BLOCKED4/24" dev src0
src ip addr add "$POLICY4/24" dev src0
src ip addr add "$HS4/24" dev src0
src ip addr add "$TTL1_4/24" dev src0
src ip addr add "$SLOWACK4/24" dev src0
src ip addr add "$RSTACK4/24" dev src0
src ip -6 addr add "$SRC6/64" dev src0 nodad
src ip -6 addr add "$HS6/64" dev src0 nodad
src ip -6 addr add "$SLOWACK6/64" dev src0 nodad
src ip -6 addr add "$RSTACK6/64" dev src0 nodad
scr ip addr add "$OUT4/24" dev out0
scr ip -6 addr add "$OUT6/64" dev out0 nodad
scr ip addr add "$IN4/24" dev in0
scr ip -6 addr add "$IN6/64" dev in0 nodad
dst ip addr add "$DST4/24" dev dst0
dst ip -6 addr add "$DST6/64" dev dst0 nodad
for ns in "$NS_SRC" "$NS_SCR" "$NS_DST"; do ip -n "$ns" link set lo up; done
src ip link set src0 up; scr ip link set out0 up; scr ip link set in0 up; dst ip link set dst0 up
src ip route add default via "$OUT4"; src ip -6 route add default via "$OUT6"
dst ip route add default via "$IN4";  dst ip -6 route add default via "$IN6"
scr ip route add 10.201.3.0/24 via "$DST4"; scr ip -6 route add fd01:3::/64 via "$DST6"
# New namespaces may inherit forwarding from the host; the HOLE prefixes rely on
# the destination silently dropping what it does not own.
dst sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0

scr sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
  net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.out0.rp_filter=0
# XDP_REDIRECT into a veth needs NAPI on the receiving peer.
dst ethtool -K dst0 gro on >/dev/null
# Locally generated packets leave the checksum to offload, and XDP_REDIRECT
# loses that state; packets from a real wire carry complete checksums.
src ethtool -K src0 tx off >/dev/null

ip netns exec "$NS_DST" python3 -m http.server 8080 --bind :: >/dev/null 2>&1 &
HTTP_PID=$!

METRICS=127.0.0.1:2112
launch_collector() {
  ip netns exec "$NS_SCR" "$COLLECTOR_BIN" -mode scrub -i out0 -inside-if in0 -metrics-addr "$METRICS" \
    -socket "" -analyzer-addr 127.0.0.1:1 -policy "$POLICY4/32=block" "$@" >>"$COLLECTOR_LOG" 2>&1 &
  COLLECTOR_PID=$!
}
start_collector() {
  launch_collector "$@"
  for _ in $(seq 50); do
    [[ "$(scr curl -s -o /dev/null -w '%{http_code}' "http://$METRICS/readyz" || true)" == 200 ]] && return 0
    kill -0 "$COLLECTOR_PID" 2>/dev/null || { tail -20 "$COLLECTOR_LOG"; die "collector exited"; }
    sleep 0.2
  done
  scr curl -s "http://$METRICS/readyz" || true
  die "collector never became ready"
}
stop_collector() {
  kill -9 "$COLLECTOR_PID" 2>/dev/null || true
  wait "$COLLECTOR_PID" 2>/dev/null || true
  COLLECTOR_PID=""
}

# metric NAME [LABELS] prints the current value (0 if absent).
metric() {
  local name="$1"
  [[ -n "${2:-}" ]] && name="$1{$2}"
  scr curl -s "http://$METRICS/metrics" | awk -v n="$name" '$1 == n {print $2; f=1} END {if (!f) print 0}'
}
increased() { awk -v a="$1" -v b="$2" 'BEGIN {exit !(b > a)}'; }
http_ok() { src curl -sS -o /dev/null --max-time 3 "$@"; }

# Map names are global across namespaces, so resolve the map that the
# attached xdp_scrub actually uses.
scrub_map_id() {
  local prog
  prog=$(scr bpftool -j net show dev out0 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["xdp"][0]["id"])')
  bpftool -j prog show id "$prog" | python3 -c '
import json, subprocess, sys
for mid in json.load(sys.stdin)["map_ids"]:
    m = json.loads(subprocess.check_output(["bpftool", "-j", "map", "show", "id", str(mid)]))
    if m["name"] == sys.argv[1]:
        print(mid)' "$1"
}

# ---- tests -----------------------------------------------------------------
log "generic XDP is refused without -allow-generic"
if scr "$COLLECTOR_BIN" -mode scrub -i out0 -inside-if in0 -xdp-mode generic -socket "" \
     -metrics-addr 127.0.0.1:2113 -analyzer-addr 127.0.0.1:1 >/dev/null 2>&1; then
  bad "collector started with -xdp-mode generic"
else
  pass "generic XDP refused"
fi

log "IPv6 forwarding is required when IPv6 is routed via the inside port"
scr sysctl -qw net.ipv6.conf.all.forwarding=0
if scr "$COLLECTOR_BIN" -mode scrub -i out0 -inside-if in0 -socket "" \
     -metrics-addr 127.0.0.1:2113 -analyzer-addr 127.0.0.1:1 >/dev/null 2>&1; then
  bad "collector started with net.ipv6.conf.all.forwarding=0"
else
  pass "IPv6 forwarding off refused"
fi
scr sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv6.conf.out0.forwarding=1 net.ipv4.conf.out0.forwarding=0
if scr "$COLLECTOR_BIN" -mode scrub -i out0 -inside-if in0 -socket "" \
     -metrics-addr 127.0.0.1:2113 -analyzer-addr 127.0.0.1:1 >/dev/null 2>&1; then
  bad "collector started with net.ipv4.conf.out0.forwarding=0"
else
  pass "IPv4 forwarding off on the outside port refused"
fi
scr sysctl -qw net.ipv4.conf.out0.forwarding=1

log "starting collector in scrub mode"
start_collector
pass "/readyz is 200"

fwd4=$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="forward"')
http_ok "http://$DST4:8080/" && pass "IPv4 TCP forwarded" || bad "IPv4 TCP to $DST4 failed"
increased "$fwd4" "$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="forward"')" \
  && pass "IPv4 forwarded in XDP" || bad "forward{ipv4} did not increase"

fwd6=$(metric packetyeeter_scrub_packets_total 'family="ipv6",verdict="forward"')
http_ok -6 "http://[$DST6]:8080/" && pass "IPv6 TCP forwarded" || bad "IPv6 TCP to $DST6 failed"
increased "$fwd6" "$(metric packetyeeter_scrub_packets_total 'family="ipv6",verdict="forward"')" \
  && pass "IPv6 forwarded in XDP" || bad "forward{ipv6} did not increase"

dst python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 5353)); s.settimeout(3)
n = 0
try:
    while n < 20:
        s.recv(2048); n += 1
except socket.timeout:
    pass
print(n)' >"$UDP_OUT" &
UDP_PID=$!
sleep 0.5
src python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(20): s.sendto(b"x" * 64, ("'"$DST4"'", 5353))'
wait "$UDP_PID" || true
[[ "$(cat "$UDP_OUT")" == 20 ]] && pass "IPv4 UDP forwarded" || bad "UDP: received $(cat "$UDP_OUT")/20"

drop4=$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="drop"')
http_ok --interface "$POLICY4" "http://$DST4:8080/" && bad "policy-blocked source got through" || pass "policy-blocked source dropped"
bpftool map update id "$(scrub_map_id blocked_ips)" key ${BLOCKED4//./ } value 0 0 0 0 0 0 0 0
http_ok --interface "$BLOCKED4" "http://$DST4:8080/" && bad "blocked_ips source got through" || pass "blocked_ips source dropped"
increased "$drop4" "$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="drop"')" \
  && pass "drop{ipv4} counted" || bad "drop{ipv4} did not increase"
http_ok "http://$DST4:8080/" && pass "other sources unaffected" || bad "clean source broken after blocks"

drop4=$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="drop"')
src ping -c1 -W1 -I "$POLICY4" "$OUT4" >/dev/null 2>&1 && bad "policy-blocked source reached the node" || pass "policy applies to the node's own addresses"
src ping -c1 -W1 -I "$BLOCKED4" "$IN4" >/dev/null 2>&1 && bad "blocked_ips source reached the node" || pass "blocked_ips applies to the node's own addresses"
increased "$drop4" "$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="drop"')" \
  && pass "local drops counted" || bad "drop{ipv4} did not increase for local traffic"

local4=$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="local"')
src ping -c1 -W1 "$OUT4" >/dev/null && src ping -c1 -W1 "$IN4" >/dev/null \
  && pass "node's own addresses reachable" || bad "ping to the scrub node failed"
increased "$local4" "$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="local"')" \
  && pass "local{ipv4} counted" || bad "local{ipv4} did not increase"

ttl=$(metric packetyeeter_scrub_ttl_expired_total)
out=$(src ping -c1 -W1 -t1 "$DST4" 2>&1 || true)
grep -qi "exceeded" <<<"$out" && pass "TTL 1 answered with time exceeded" || bad "no ICMP time exceeded: $out"
increased "$ttl" "$(metric packetyeeter_scrub_ttl_expired_total)" && pass "ttl_expired counted" || bad "ttl_expired did not increase"

neigh=$(metric packetyeeter_scrub_slow_path_total 'reason="no_neigh"')
scr ip neigh flush dev in0
http_ok "http://$DST4:8080/" && http_ok "http://$DST4:8080/" && pass "traffic recovers after neighbour flush" || bad "no recovery after neighbour flush"
increased "$neigh" "$(metric packetyeeter_scrub_slow_path_total 'reason="no_neigh"')" \
  && pass "slow_path{no_neigh} counted" || bad "slow_path{no_neigh} did not increase"

log "handshake tracking"
stop_collector
mkfifo "$CMD_FIFO"
# Held open read-write so the sink never sees EOF between commands.
exec 3<>"$CMD_FIFO"
ip netns exec "$NS_SCR" "$SINK_BIN" 127.0.0.1:59999 "$CMD_FIFO" >"$SINK_LOG" 2>&1 &
SINK_PID=$!
sleep 0.5
start_collector -analyzer-addr 127.0.0.1:59999 -handshake-timeout 1s
# Kernel map names stop at 15 characters, so both families share this name.
hs_flags=$(for id in $(scrub_map_id scrub_handshake); do
  bpftool -j map show id "$id" | python3 -c 'import json, sys; print(json.load(sys.stdin)["flags"])'
done | sort | uniq -c | awk '{print $1 "x" $2}')
# BPF_F_NO_COMMON_LRU is 2.
[[ "$hs_flags" == 2x2 && -z "$(scrub_map_id pending_handsha)" ]] \
  && pass "xdp_scrub tracks handshakes in its own per-CPU LRU maps" \
  || bad "scrub handshake maps: flags ${hs_flags:-none}, host maps: $(scrub_map_id pending_handsha | xargs)"
# Resolve the inside neighbours first: a SYN that takes the kernel path is not
# tracked, which would make the check below vacuous. Bind the sources, since
# Linux would otherwise pick the newest address (HS6).
src ping -c1 -W1 "$DST4" >/dev/null; src ping -c1 -W1 "$DST6" >/dev/null
http_ok --interface "$SRC4" "http://$DST4:8080/" && http_ok -6 --interface "$SRC6" "http://[$DST6]:8080/" \
  || bad "completed handshakes failed"
syn_only() { # SOURCE DEST [TTL]: a connect() that never completes
  src python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6 if ":" in sys.argv[2] else socket.AF_INET)
if len(sys.argv) > 3:
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, int(sys.argv[3]))
s.bind((sys.argv[1], 0)); s.settimeout(1.5)
try:
    s.connect((sys.argv[2], 80))
except OSError:
    pass' "$@"
}
syn_only "$HS4" "$HOLE4" & syn4=$!
syn_only "$HS6" "$HOLE6" & syn6=$!
syn_only "$TTL1_4" "$DST4" 1 & synttl=$!
wait "$syn4" "$syn6" "$synttl"
raw_tcp() { # SRC DST then FLAGS:TTL pairs, sent in order on one 4-tuple
  src python3 -c '
import socket, struct, sys
src, dst = sys.argv[1], sys.argv[2]
v6 = ":" in dst
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF
if v6:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.bind((src, 0))
else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
for pair in sys.argv[3:]:
    flags, ttl = (int(x, 0) for x in pair.split(":"))
    tcp = struct.pack("!HHIIBBHHH", 40001, 80, 1000, 1, 5 << 4, flags, 64240, 0, 0)
    if v6:
        pseudo = (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
                  + struct.pack("!I3xB", len(tcp), 6))
    else:
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    if v6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        sock.sendto(tcp, (dst, 0))
        continue
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, ttl, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    sock.sendto(ip + tcp, (dst, 0))' "$@"
}
raw_tcp "$SLOWACK4" "$HOLE4" 0x02:64 0x10:1
raw_tcp "$RSTACK4" "$HOLE4" 0x02:64 0x14:64
raw_tcp "$SLOWACK6" "$HOLE6" 0x02:64 0x10:1
raw_tcp "$RSTACK6" "$HOLE6" 0x02:64 0x14:64
reported() { grep -q "type=SIGNAL_INCOMPLETE_HANDSHAKE .*ip=$1\$" "$SINK_LOG"; }
# The RST|ACK sources are sent last; waiting only for HS4/HS6 left them less
# than one poll of slack.
for _ in $(seq 30); do
  reported "$HS4" && reported "$HS6" && reported "$RSTACK4" && reported "$RSTACK6" && break
  sleep 0.2
done
sleep 2 # two more polls, so an expired entry for a completed handshake would have surfaced
reported "$HS4" && pass "unanswered IPv4 SYN reported as incomplete handshake" || bad "no incomplete handshake signal for $HS4"
reported "$HS6" && pass "unanswered IPv6 SYN reported as incomplete handshake" || bad "no incomplete handshake signal for $HS6"
reported "$SRC4" || reported "$SRC6" && bad "completed handshake reported as incomplete" || pass "completed handshakes not reported"
reported "$TTL1_4" && bad "SYN the node did not forward was reported" || pass "SYNs left to the kernel not reported"
reported "$SLOWACK4" && bad "handshake whose ACK took the kernel path was reported" || pass "ACKs left to the kernel still complete a handshake"
reported "$RSTACK4" && pass "RST|ACK does not count as a completed handshake" || bad "RST|ACK closed the handshake"
reported "$SLOWACK6" && bad "IPv6 handshake whose ACK took the kernel path was reported" || pass "IPv6 ACKs left to the kernel still complete a handshake"
reported "$RSTACK6" && pass "IPv6 RST|ACK does not count as a completed handshake" || bad "IPv6 RST|ACK closed the handshake"

log "runtime rules"
EXPIRES=$(date -u -d '+10 min' +%FT%TZ)
send_rules() { # RuleSetDelta as protojson; the sink reads one command per line
  local sent
  sent=$(grep -c "^SENT type=COMMAND_SET_RULES collectors=1" "$SINK_LOG" || true)
  printf '{"type":"COMMAND_SET_RULES","rules":%s}\n' "$(tr -d '\n' <<<"$1")" >&3
  for _ in $(seq 30); do
    (( $(grep -c "^SENT type=COMMAND_SET_RULES collectors=1" "$SINK_LOG" || true) > sent )) && { sleep 0.5; return 0; }
    sleep 0.1
  done
  bad "rule delta not delivered to the collector"
}
udp_recv() { # PORT SECONDS: prints how many datagrams arrived
  dst python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::", int(sys.argv[1]))); s.settimeout(float(sys.argv[2]))
n = 0
try:
    while True:
        s.recv(2048); n += 1
except socket.timeout:
    pass
print(n)' "$1" "$2"
}
udp_send() { # SRC SPORT DST DPORT COUNT PPS [PAYLOAD_BYTES]
  src python3 -c '
import socket, sys, time
src, sport, dst, dport, count, pps = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), float(sys.argv[6])
size = int(sys.argv[7]) if len(sys.argv) > 7 else 64
s = socket.socket(socket.AF_INET6 if ":" in dst else socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, sport))
start = time.monotonic()
for i in range(count):
    s.sendto(b"x" * size, (dst, dport))
    delay = start + (i + 1) / pps - time.monotonic()
    if delay > 0:
        time.sleep(delay)
print(f"{time.monotonic() - start:.3f}")' "$@"
}
udp_through() { # SRC SPORT DST DPORT COUNT: prints datagrams delivered
  udp_recv "$4" 2 >"$UDP_OUT" & local r=$!
  sleep 0.3
  udp_send "$1" "$2" "$3" "$4" "$5" 200 >/dev/null
  wait "$r" || true; cat "$UDP_OUT"
}

drops=$(metric packetyeeter_scrub_rule_matches_total 'action="drop"')
incidents=$(metric packetyeeter_kernel_incidents_total 'reason="rule_match"')
send_rules '{"upsert":[
  {"id":"ntp-v4","dstPrefix":"'"$DST4"'/32","protocols":[17],"srcPorts":[{"from":123,"to":123}],"action":"RULE_ACTION_DROP","priority":5,"expiresAt":"'"$EXPIRES"'"},
  {"id":"ntp-v6","dstPrefix":"'"$DST6"'/128","protocols":[17],"srcPorts":[{"from":123,"to":123}],"action":"RULE_ACTION_DROP","expiresAt":"'"$EXPIRES"'"},
  {"id":"trusted","dstPrefix":"10.201.0.0/16","srcPrefixes":["'"$POLICY4"'/32"],"action":"RULE_ACTION_PASS","priority":1,"expiresAt":"'"$EXPIRES"'"}]}'
[[ "$(metric packetyeeter_scrub_rules_active 'family="ipv4"')" == 2 && "$(metric packetyeeter_scrub_rules_active 'family="ipv6"')" == 1 ]] \
  && pass "rules installed" || bad "rules_active: $(metric packetyeeter_scrub_rules_active 'family="ipv4"') v4, $(metric packetyeeter_scrub_rules_active 'family="ipv6"') v6"
[[ "$(udp_through "$SRC4" 123 "$DST4" 5400 20)" == 0 ]] && pass "DROP rule drops UDP from port 123" || bad "UDP from port 123 got through"
[[ "$(udp_through "$SRC4" 124 "$DST4" 5400 20)" == 20 ]] && pass "DROP rule leaves port 124 alone" || bad "UDP from port 124 was dropped"
[[ "$(udp_through "$SRC6" 123 "$DST6" 5400 20)" == 0 ]] && pass "IPv6 DROP rule drops UDP from port 123" || bad "IPv6 UDP from port 123 got through"
[[ "$(udp_through "$SRC6" 124 "$DST6" 5400 20)" == 20 ]] && pass "IPv6 DROP rule leaves port 124 alone" || bad "IPv6 UDP from port 124 was dropped"
increased "$drops" "$(metric packetyeeter_scrub_rule_matches_total 'action="drop"')" \
  && pass "rule_matches{drop} counted" || bad "rule_matches{drop} did not increase"
increased "$incidents" "$(metric packetyeeter_kernel_incidents_total 'reason="rule_match"')" \
  && pass "rule_match incidents counted" || bad "no rule_match incidents"
# The /16 PASS rule outranks the more specific /32 rule and skips -policy.
http_ok --interface "$POLICY4" "http://$DST4:8080/" && pass "PASS rule on a covering prefix skips -policy" || bad "PASS rule did not let the policy-blocked source through"

send_rules '{"upsert":[{"id":"rl","dstPrefix":"'"$DST4"'/32","protocols":[17],"dstPorts":[{"from":5401,"to":5401}],"action":"RULE_ACTION_RATE_LIMIT","ratePps":"200","expiresAt":"'"$EXPIRES"'"}]}'
udp_recv 5401 1.5 >"$UDP_OUT" & r=$!
sleep 0.3
secs=$(udp_send "$SRC4" 0 "$DST4" 5401 2000 1000)
wait "$r" || true
got=$(cat "$UDP_OUT")
# 200 pps over however long sending took, +-10%, plus one 100ms window of
# slack for a partly used first or last window.
read -r lo hi want < <(awk -v s="$secs" 'BEGIN { w = 200 * s; printf "%d %d %d\n", w * 0.9 - 20, w * 1.1 + 20, w }')
(( got >= lo && got <= hi )) && pass "RATE_LIMIT holds 200 pps ($got/$want in ${secs}s)" || bad "RATE_LIMIT let $got through in ${secs}s, want $lo-$hi"

send_rules '{"upsert":[
  {"id":"ok","dstPrefix":"'"$DST4"'/32","protocols":[17],"dstPorts":[{"from":5402,"to":5402}],"action":"RULE_ACTION_DROP","expiresAt":"'"$EXPIRES"'"},
  {"id":"bad","dstPrefix":"'"$DST4"'/32","action":"RULE_ACTION_DROP"}]}'
[[ "$(udp_through "$SRC4" 0 "$DST4" 5402 20)" == 20 ]] && grep -q "Rejected rule delta" "$COLLECTOR_LOG" \
  && pass "a delta with an invalid rule is rejected whole" || bad "partial delta applied"

send_rules '{"remove":["ntp-v4"]}'
[[ "$(udp_through "$SRC4" 123 "$DST4" 5400 20)" == 20 ]] && pass "removed rule stops matching" || bad "removed rule still drops"

expiry=$(date +%s.%N | awk '{ printf "%.3f", $1 + 3 }')
SOON=$(date -u -d "@$expiry" +%FT%T.%3NZ)
drops=$(metric packetyeeter_scrub_rule_matches_total 'action="drop"')
send_rules '{"upsert":[{"id":"short","dstPrefix":"'"$DST4"'/32","protocols":[6],"dstPorts":[{"from":8080,"to":8080}],"action":"RULE_ACTION_DROP","expiresAt":"'"$SOON"'"}]}'
http_ok --max-time 1 "http://$DST4:8080/" 2>/dev/null || true
increased "$drops" "$(metric packetyeeter_scrub_rule_matches_total 'action="drop"')" \
  && pass "short-lived DROP rule matches" || bad "short-lived DROP rule did not match"
sleep "$(awk -v e="$expiry" -v n="$(date +%s.%N)" 'BEGIN { d = e + 2 - n; print (d > 0 ? d : 0) }')"
http_ok "http://$DST4:8080/" && pass "expired rule stops matching within 2s" || bad "expired rule still drops 2s after expiry"

log "4096 rules"
send_rules '{"remove":["ntp-v6","trusted","rl","short"]}'
# 31 rules on a covering /16 plus 4065 /32s: every /32 entry lists 32 rules,
# the per-destination maximum.
many=$(python3 -c '
import json, sys
rules = [{"id": f"c{i}", "dstPrefix": "10.210.0.0/16", "protocols": [17], "dstPorts": [{"from": 9000 + i, "to": 9000 + i}],
          "action": "RULE_ACTION_DROP", "priority": i, "expiresAt": sys.argv[1]} for i in range(31)]
rules += [{"id": f"r{i}", "dstPrefix": f"10.210.{i >> 8}.{i & 255}/32", "protocols": [17],
           "action": "RULE_ACTION_DROP", "priority": 100, "expiresAt": sys.argv[1]} for i in range(4065)]
print(json.dumps({"upsert": rules}))' "$EXPIRES")
t0=$(date +%s.%N)
send_rules "$many"
for _ in $(seq 40); do [[ "$(metric packetyeeter_scrub_rules_active 'family="ipv4"')" == 4096 ]] && break; sleep 0.25; done
t1=$(date +%s.%N)
[[ "$(metric packetyeeter_scrub_rules_active 'family="ipv4"')" == 4096 ]] \
  && pass "4096 IPv4 rules installed in $(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')s" || bad "rules_active=$(metric packetyeeter_scrub_rules_active 'family="ipv4"') after loading 4096"
http_ok "http://$DST4:8080/" && pass "forwarding unaffected with 4096 rules" || bad "forwarding broken with 4096 rules"
send_rules "$(python3 -c 'import json; print(json.dumps({"remove": [f"c{i}" for i in range(31)] + [f"r{i}" for i in range(4065)]}))')"

log "fingerprints"
stop_collector
connects() { grep -c "Connected to analyzer" "$COLLECTOR_LOG" || true; }
start_fp_collector() { # extra collector flags; waits for the analyzer stream
  local before
  before=$(connects)
  start_collector -analyzer-addr 127.0.0.1:59999 "$@"
  for _ in $(seq 50); do (( $(connects) > before )) && return 0; sleep 0.1; done
  bad "collector did not connect to the analyzer sink"
}
# fp_seen DST DPORT SIZE SRC_NET DROPPED: a matching bucket arrived whose
# bytes are 516/496 per packet (468-byte payload over IPv6/IPv4).
fp_seen() {
  local per=496; [[ "$1" == *:* ]] && per=516
  awk -v d="dst=$1" -v p="dport=$2" -v z="size=$3" -v n="src_net=$4" -v x="dropped=$5" -v per="$per" '
    $1 == "FINGERPRINT" && $3 == d && $4 == "proto=17" && $5 == p && $6 == z && $7 == "ttl=2" && $8 == n && $9 == x {
      split($10, a, "="); split($11, b, "=")
      if (a[2] > 0 && b[2] == a[2] * per) found = 1
    } END { exit !found }' "$SINK_LOG"
}
wait_fp() { for _ in $(seq 60); do fp_seen "$@" && return 0; sleep 0.1; done; return 1; }
start_fp_collector -fingerprint-interval 2s
# NTP-like reflection traffic: source port 123, 468-byte payload.
udp_send "$SRC4" 123 "$DST4" 5410 20 200 468 >/dev/null
udp_send "$SRC6" 123 "$DST6" 5410 20 200 468 >/dev/null
wait_fp "$DST4" 5410 2 10.201.1.0 false && pass "IPv4 fingerprint: UDP, size bucket 2, forwarded" \
  || bad "no IPv4 fingerprint for $DST4:5410: $(grep FINGERPRINT "$SINK_LOG" | tail -3)"
wait_fp "$DST6" 5410 3 fd01:1:: false && pass "IPv6 fingerprint: UDP, size bucket 3, source /48" \
  || bad "no IPv6 fingerprint for [$DST6]:5410: $(grep FINGERPRINT "$SINK_LOG" | tail -3)"
grep -q "^FINGERPRINT collector=$(scr hostname) " "$SINK_LOG" && pass "fingerprints carry the collector's hostname" \
  || bad "fingerprint collector_id is not $(scr hostname)"
send_rules '{"upsert":[
  {"id":"fp-ntp-v4","dstPrefix":"'"$DST4"'/32","protocols":[17],"srcPorts":[{"from":123,"to":123}],"action":"RULE_ACTION_DROP","expiresAt":"'"$EXPIRES"'"},
  {"id":"fp-ntp-v6","dstPrefix":"'"$DST6"'/128","protocols":[17],"srcPorts":[{"from":123,"to":123}],"action":"RULE_ACTION_DROP","expiresAt":"'"$EXPIRES"'"}]}'
udp_send "$SRC4" 123 "$DST4" 5410 20 200 468 >/dev/null
udp_send "$SRC6" 123 "$DST6" 5410 20 200 468 >/dev/null
wait_fp "$DST4" 5410 2 10.201.1.0 true && pass "IPv4 fingerprint of rule-dropped traffic has dropped=true" \
  || bad "no dropped IPv4 fingerprint: $(grep FINGERPRINT "$SINK_LOG" | tail -3)"
wait_fp "$DST6" 5410 3 fd01:1:: true && pass "IPv6 fingerprint of rule-dropped traffic has dropped=true" \
  || bad "no dropped IPv6 fingerprint: $(grep FINGERPRINT "$SINK_LOG" | tail -3)"
increased 0 "$(metric packetyeeter_scrub_fingerprint_buckets)" && pass "fingerprint_buckets exported" \
  || bad "packetyeeter_scrub_fingerprint_buckets is $(metric packetyeeter_scrub_fingerprint_buckets)"
[[ "$(metric packetyeeter_scrub_fingerprint_overflow_total)" == 0 ]] && pass "no fingerprint overflow" \
  || bad "fingerprint overflow: $(metric packetyeeter_scrub_fingerprint_overflow_total)"

stop_collector
start_fp_collector -fingerprint-interval 0
seen=$(grep -c "^FINGERPRINT" "$SINK_LOG" || true)
udp_send "$SRC4" 123 "$DST4" 5411 20 200 468 >/dev/null
sleep 3
[[ "$(grep -c "^FINGERPRINT" "$SINK_LOG" || true)" == "$seen" ]] && pass "-fingerprint-interval 0 sends no fingerprints" \
  || bad "fingerprints sent with -fingerprint-interval 0"

log "IPv6 transit with forwarding disabled is visible"
nf=$(metric packetyeeter_scrub_slow_path_total 'reason="not_fwded"')
scr sysctl -qw net.ipv6.conf.all.forwarding=0
code=$(scr curl -s -o /dev/null -w '%{http_code}' "http://$METRICS/readyz" || true)
[[ "$code" == 503 ]] && pass "/readyz 503 with IPv6 forwarding off" || bad "/readyz=$code with IPv6 forwarding off"
http_ok -6 --max-time 1 "http://[$DST6]:8080/" || true
increased "$nf" "$(metric packetyeeter_scrub_slow_path_total 'reason="not_fwded"')" \
  && pass "slow_path{not_fwded} counted" || bad "slow_path{not_fwded} did not increase"
scr sysctl -qw net.ipv6.conf.all.forwarding=1
code=$(scr curl -s -o /dev/null -w '%{http_code}' "http://$METRICS/readyz" || true)
[[ "$code" == 200 ]] && pass "/readyz recovers with IPv6 forwarding on" || bad "/readyz=$code after re-enabling IPv6 forwarding"

log "slow-path rate limit"
stop_collector
start_collector -scrub-slow-path-pps 1
lim=$(metric packetyeeter_scrub_slow_path_limited_total)
src ping -q -c 100 -i 0.005 -W1 -t1 "$DST4" >/dev/null 2>&1 || true
increased "$lim" "$(metric packetyeeter_scrub_slow_path_limited_total)" \
  && pass "slow_path_limited counted" || bad "slow_path_limited did not increase"
http_ok "http://$DST4:8080/" && pass "fast path unaffected by the slow-path limit" || bad "forwarding broken with slow-path limit"

log "routing loop"
# A leaked redirect route: the inside sends the prefix back to the edge, which
# redirects it to the outside port again. Each lap costs four TTL (edge, XDP,
# destination, scrub kernel); pings with TTL 61-64 make sure one of them
# reaches xdp_scrub with TTL 1.
scr ip route add 10.201.4.0/24 via "$DST4"
scr ip rule add iif in0 to 10.201.4.0/24 lookup 104
scr ip route add 10.201.4.0/24 via "$SRC4" dev out0 table 104
src ip route add 10.201.4.0/24 via "$OUT4"
# The edge sees its own echo requests come back; accept_local lets it forward them.
# New namespaces inherit these from the host, so restore rather than zero them.
src_saved=$(src sysctl -n net.ipv4.ip_forward net.ipv4.conf.all.accept_local net.ipv4.conf.src0.accept_local | tr '\n' ' ')
dst_fwd=$(dst sysctl -n net.ipv4.ip_forward)
src sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.accept_local=1 net.ipv4.conf.src0.accept_local=1
dst sysctl -qw net.ipv4.ip_forward=1
ttl=$(metric packetyeeter_scrub_ttl_expired_total)
for t in 61 62 63 64; do src ping -c1 -W1 -t "$t" 10.201.4.9 >/dev/null 2>&1 || true; done
increased "$ttl" "$(metric packetyeeter_scrub_ttl_expired_total)" \
  && pass "routing loop shows up in ttl_expired" || bad "ttl_expired did not increase on a routing loop"
dst sysctl -qw net.ipv4.ip_forward="$dst_fwd"
read -r fwd al al0 <<<"$src_saved"
src sysctl -qw net.ipv4.ip_forward="$fwd" net.ipv4.conf.all.accept_local="$al" net.ipv4.conf.src0.accept_local="$al0"
src ip route del 10.201.4.0/24
scr ip route del 10.201.4.0/24 table 104
scr ip rule del iif in0 to 10.201.4.0/24 lookup 104
scr ip route del 10.201.4.0/24

log "monitor mode"
stop_collector
start_collector -dry-run -analyzer-addr 127.0.0.1:59999
http_ok --interface "$POLICY4" "http://$DST4:8080/" && pass "monitor mode forwards a policy-blocked source" || bad "monitor mode dropped traffic"
drops=$(metric packetyeeter_scrub_rule_matches_total 'action="drop"')
send_rules '{"upsert":[{"id":"ntp-monitor","dstPrefix":"'"$DST4"'/32","protocols":[17],"srcPorts":[{"from":123,"to":123}],"action":"RULE_ACTION_DROP","expiresAt":"'"$EXPIRES"'"}]}'
[[ "$(udp_through "$SRC4" 123 "$DST4" 5400 20)" == 20 ]] && pass "monitor mode forwards traffic a DROP rule matches" || bad "monitor mode dropped rule-matched traffic"
increased "$drops" "$(metric packetyeeter_scrub_rule_matches_total 'action="drop"')" \
  && pass "monitor mode still counts rule matches" || bad "no rule matches counted in monitor mode"
[[ "$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="drop"')" == 0 ]] \
  && pass "monitor mode dropped nothing" || bad "drop{ipv4} non-zero in monitor mode"

log "SYN cookies"
stop_collector
# Kernels without the XDP SYN cookie helpers (< 6.0) must refuse the flag.
if [[ "$(printf '%s\n' 6.0 "$(uname -r)" | sort -V | head -1)" != 6.0 ]]; then
  if scr "$COLLECTOR_BIN" -mode scrub -i out0 -inside-if in0 -socket "" -scrub-syn-cookies on \
       -metrics-addr 127.0.0.1:2113 -analyzer-addr 127.0.0.1:1 >/dev/null 2>&1; then
    bad "-scrub-syn-cookies accepted on kernel $(uname -r)"
  else
    pass "-scrub-syn-cookies refused on kernel $(uname -r)"
  fi
  start_collector
else
# Challenges leave by XDP_TX, which a veth only delivers promptly when its
# peer runs an XDP program too.
XDP_PASS_OBJ="$(mktemp /tmp/yeet-xdp-pass.XXXXXX.o)"
printf '%s\n' '#include <linux/bpf.h>' \
  '__attribute__((section("xdp"), used)) int xdp_pass(struct xdp_md *ctx) { return XDP_PASS; }' \
  'char LICENSE[] __attribute__((section("license"), used)) = "GPL";' \
  | clang -O2 -target bpf -I"/usr/include/$(gcc -dumpmachine)" -x c -c - -o "$XDP_PASS_OBJ"
src ip link set dev src0 xdpdrv obj "$XDP_PASS_OBJ" sec xdp
SC_PORT=9
# Spoofed-source SYNs go to port 9; tc counts what reaches the destination
# and the SYN-ACKs the node sends back, and drops both.
dst tc qdisc add dev dst0 clsact
dst tc filter add dev dst0 ingress pref 10 protocol ip flower ip_proto tcp dst_port "$SC_PORT" action drop
dst tc filter add dev dst0 ingress pref 11 protocol ipv6 flower ip_proto tcp dst_port "$SC_PORT" action drop
src tc qdisc add dev src0 clsact
src tc filter add dev src0 ingress pref 10 protocol ip flower ip_proto tcp src_port "$SC_PORT" action drop
src tc filter add dev src0 ingress pref 11 protocol ipv6 flower ip_proto tcp src_port "$SC_PORT" action drop
tc_count() { # NS PREF
  ip netns exec "$1" tc -s filter show dev "$([[ $1 == "$NS_DST" ]] && echo dst0 || echo src0)" ingress pref "$2" \
    | awk '/Sent/ {print $4; exit}'
}
OUT_MAC=$(scr cat /sys/class/net/out0/address)
SRC_MAC=$(src cat /sys/class/net/src0/address)
FLOOD_CFG="$(mktemp /tmp/yeet-scrub-flood.XXXXXX.cfg)"
printf '%s\n' \
  "{ eth(da=$OUT_MAC, sa=$SRC_MAC), ipv4(saddr=drnd(), daddr=$DST4, ttl=64), tcp(sp=drnd(), dp=$SC_PORT, syn, seq=drnd(), win=64240) }" \
  "{ eth(da=$OUT_MAC, sa=$SRC_MAC), ipv6(sa=drnd(), da=$DST6, hl=64), tcp(sp=drnd(), dp=$SC_PORT, syn, seq=drnd(), win=64240) }" \
  >"$FLOOD_CFG"
FLOOD=2000
# flood COUNT: COUNT spoofed SYNs per family; sets F4/F6 (SYNs the
# destination got) and A4/A6 (SYN-ACKs back to the sources).
flood() {
  local d4 d6 a4 a6
  d4=$(tc_count "$NS_DST" 10); d6=$(tc_count "$NS_DST" 11)
  a4=$(tc_count "$NS_SRC" 10); a6=$(tc_count "$NS_SRC" 11)
  src trafgen -o src0 -i "$FLOOD_CFG" -n "$((2 * $1))" -P 1 >/dev/null 2>&1 || bad "trafgen failed"
  sleep 0.5
  F4=$(( $(tc_count "$NS_DST" 10) - d4 )); F6=$(( $(tc_count "$NS_DST" 11) - d6 ))
  A4=$(( $(tc_count "$NS_SRC" 10) - a4 )); A6=$(( $(tc_count "$NS_SRC" 11) - a6 ))
}
sc() { metric packetyeeter_scrub_syncookie_total "event=\"$2\",family=\"$1\""; }
connect_time() { # curl args: prints the TCP connect time in ms, fails if curl does
  src curl -sS -o /dev/null --max-time 5 -w '%{time_connect}' "$@" | awk '{printf "%.0f", $1 * 1000}'
}

if command -v trafgen >/dev/null; then
  start_collector
  http_ok "http://$DST4:8080/" && http_ok -6 "http://[$DST6]:8080/" || bad "clean traffic failed before the flood"
  flood "$FLOOD"
  (( F4 >= FLOOD * 9 / 10 && F6 >= FLOOD * 9 / 10 )) && pass "cookies off: spoofed SYNs forwarded (v4 $F4, v6 $F6 of $FLOOD)" \
    || bad "cookies off: destination got v4 $F4, v6 $F6 of $FLOOD spoofed SYNs"
  stop_collector
else
  log "trafgen not installed: skipping the spoofed-flood checks"
fi

start_collector -scrub-syn-cookies on
for fam in ipv4 ipv6; do
  url="http://$DST4:8080/"; [[ $fam == ipv6 ]] && url="http://[$DST6]:8080/"
  ms=$(connect_time "$url") && pass "$fam client connects through a challenge (connect ${ms} ms)" || bad "$fam client failed with cookies on"
  increased 0 "$(sc $fam challenge)" && increased 0 "$(sc $fam valid)" \
    && pass "$fam challenge answered (challenge=$(sc $fam challenge) valid=$(sc $fam valid))" \
    || bad "$fam: challenge=$(sc $fam challenge) valid=$(sc $fam valid)"
  [[ "$(metric packetyeeter_scrub_syncookie_verified_sources "family=\"$fam\"")" -ge 1 ]] \
    && pass "$fam verified source counted" || bad "$fam verified_sources=$(metric packetyeeter_scrub_syncookie_verified_sources "family=\"$fam\"")"
  ch=$(sc $fam challenge); pa=$(sc $fam passed)
  http_ok "$url" && [[ "$(sc $fam challenge)" == "$ch" ]] && increased "$pa" "$(sc $fam passed)" \
    && pass "$fam verified source is not challenged again" || bad "$fam second connection challenged or failed"
done
if command -v trafgen >/dev/null; then
  ch4=$(sc ipv4 challenge); ch6=$(sc ipv6 challenge)
  flood "$FLOOD"
  (( F4 <= FLOOD / 100 && F6 <= FLOOD / 100 )) && pass "cookies on: spoofed SYNs not forwarded (v4 $F4, v6 $F6 of $FLOOD)" \
    || bad "cookies on: destination got v4 $F4, v6 $F6 of $FLOOD spoofed SYNs"
  (( A4 >= FLOOD * 9 / 10 && A6 >= FLOOD * 9 / 10 )) && pass "challenges sent back (v4 $A4, v6 $A6)" \
    || bad "SYN-ACKs back to the spoofed sources: v4 $A4, v6 $A6 of $FLOOD"
  (( $(sc ipv4 challenge) - ch4 >= FLOOD * 9 / 10 && $(sc ipv6 challenge) - ch6 >= FLOOD * 9 / 10 )) \
    && pass "challenge counters follow the flood" || bad "challenge counters rose by $(( $(sc ipv4 challenge) - ch4 )) / $(( $(sc ipv6 challenge) - ch6 ))"
  http_ok "http://$DST4:8080/" && http_ok -6 "http://[$DST6]:8080/" && pass "clean traffic unaffected by the flood" \
    || bad "clean traffic failed after the flood"
fi

stop_collector
start_collector -scrub-syn-cookies on -scrub-syn-cookie-style reset
for fam in ipv4 ipv6; do
  url="http://$DST4:8080/"; [[ $fam == ipv6 ]] && url="http://[$DST6]:8080/"
  # The first connection completes against the node, which resets it.
  http_ok "$url" 2>/dev/null && bad "$fam reset style: first connection succeeded" || pass "$fam reset style: first connection reset"
  increased 0 "$(sc $fam valid)" && http_ok "$url" && pass "$fam reset style: reconnect passes" \
    || bad "$fam reset style: valid=$(sc $fam valid), reconnect failed"
done

if command -v trafgen >/dev/null; then
  stop_collector
  start_collector -scrub-syn-cookies on -dry-run
  flood "$FLOOD"
  (( F4 >= FLOOD * 9 / 10 && F6 >= FLOOD * 9 / 10 )) && pass "dry run forwards spoofed SYNs (v4 $F4, v6 $F6)" \
    || bad "dry run: destination got v4 $F4, v6 $F6 of $FLOOD"
  (( A4 == 0 && A6 == 0 )) && [[ "$(sc ipv4 challenge)" == 0 && "$(sc ipv6 challenge)" == 0 ]] \
    && pass "dry run sends no challenges" || bad "dry run challenged: SYN-ACKs v4 $A4, v6 $A6"
  (( $(sc ipv4 dry_run) >= FLOOD * 9 / 10 && $(sc ipv6 dry_run) >= FLOOD * 9 / 10 )) \
    && pass "dry run counts would-be challenges (v4 $(sc ipv4 dry_run), v6 $(sc ipv6 dry_run))" \
    || bad "dry_run counters: v4 $(sc ipv4 dry_run), v6 $(sc ipv6 dry_run)"

  stop_collector
  start_collector -scrub-syn-cookies auto -scrub-syn-cookie-syn-pps 500
  http_ok "http://$DST4:8080/" && [[ "$(sc ipv4 challenge)" == 0 ]] \
    && pass "auto: no challenges below the threshold" || bad "auto: challenged without a flood ($(sc ipv4 challenge))"
  flood 20000
  (( F4 <= 1000 && F6 <= 1000 )) && pass "auto: flood challenged once over the threshold (v4 $F4, v6 $F6 of 20000 forwarded)" \
    || bad "auto: destination got v4 $F4, v6 $F6 of 20000"
  increased 0 "$(sc ipv4 activated)" && increased 0 "$(sc ipv6 activated)" \
    && pass "auto: activation counted" || bad "auto: activated v4 $(sc ipv4 activated), v6 $(sc ipv6 activated)"
  ch=$(sc ipv4 challenge)
  http_ok "http://$DST4:8080/" && increased "$ch" "$(sc ipv4 challenge)" \
    && pass "auto: clean client challenged during the flood and connects" || bad "auto: clean client not challenged or failed"
fi
rm -f "$FLOOD_CFG" "$XDP_PASS_OBJ"
src ip link set dev src0 xdpdrv off
stop_collector
start_collector
fi

log "analyzer stream: degraded by default, readiness only with -readyz-analyzer-grace"
stop_collector
readyz() { scr curl -s "http://$METRICS/readyz" || true; }
readyz_code() { scr curl -s -o /dev/null -w '%{http_code}' "http://$METRICS/readyz" || true; }
start_collector
[[ "$(readyz_code)" == 200 && "$(readyz)" == *"degraded: analyzer stream not connected yet"* ]] \
  && pass "no analyzer: /readyz 200 and reports degraded" || bad "no analyzer, default: $(readyz_code) $(readyz)"
[[ "$(metric packetyeeter_scrub_analyzer_stream_up)" == 0 ]] && increased 0 "$(metric packetyeeter_scrub_analyzer_stream_down_seconds)" \
  && pass "stream_up 0, down_seconds rising" || bad "stream_up=$(metric packetyeeter_scrub_analyzer_stream_up) down=$(metric packetyeeter_scrub_analyzer_stream_down_seconds)"
stop_collector
start_collector -analyzer-addr 127.0.0.1:59999
for _ in $(seq 25); do [[ "$(metric packetyeeter_scrub_analyzer_stream_up)" == 1 ]] && break; sleep 0.2; done
[[ "$(readyz)" == ready && "$(metric packetyeeter_scrub_analyzer_stream_down_seconds)" == 0 ]] \
  && pass "stream up: not degraded" || bad "stream up: $(readyz), down_seconds=$(metric packetyeeter_scrub_analyzer_stream_down_seconds)"
kill "$SINK_PID"; wait "$SINK_PID" 2>/dev/null || true
for _ in $(seq 25); do [[ "$(metric packetyeeter_scrub_analyzer_stream_up)" == 0 ]] && break; sleep 0.2; done
sleep 1
[[ "$(readyz_code)" == 200 && "$(readyz)" == *"degraded: analyzer stream down for"* ]] \
  && pass "analyzer lost: /readyz stays 200, reports degraded" || bad "analyzer lost, default: $(readyz_code) $(readyz)"
http_ok "http://$DST4:8080/" && pass "forwarding continues without the analyzer" || bad "forwarding stopped without the analyzer"
stop_collector

launch_collector -analyzer-addr 127.0.0.1:59999 -readyz-analyzer-grace 2s
for _ in $(seq 25); do [[ "$(readyz)" == *"analyzer: stream not connected yet"* ]] && break; sleep 0.2; done
[[ "$(readyz)" == *"analyzer: stream not connected yet"* ]] && pass "grace set: /readyz 503 until the analyzer stream is up" \
  || bad "grace set, no analyzer: $(readyz)"
ip netns exec "$NS_SCR" "$SINK_BIN" 127.0.0.1:59999 "$CMD_FIFO" >>"$SINK_LOG" 2>&1 &
SINK_PID=$!
for _ in $(seq 100); do [[ "$(readyz)" == ready ]] && break; sleep 0.2; done
[[ "$(readyz)" == ready ]] && pass "grace set: /readyz 200 once the stream is up" || bad "grace set, analyzer up: $(readyz)"
# A stream that breaks within 30s does not end the outage counted since start-up.
kill "$SINK_PID"; wait "$SINK_PID" 2>/dev/null || true
for _ in $(seq 25); do [[ "$(readyz)" == *"analyzer: stream down"* ]] && break; sleep 0.2; done
[[ "$(readyz)" == *"analyzer: stream down"* ]] && pass "grace set: short-lived stream does not restart the grace" \
  || bad "short-lived stream: $(readyz)"
ip netns exec "$NS_SCR" "$SINK_BIN" 127.0.0.1:59999 "$CMD_FIFO" >>"$SINK_LOG" 2>&1 &
SINK_PID=$!
for _ in $(seq 100); do [[ "$(readyz)" == ready ]] && break; sleep 0.2; done
sleep 31 # past analyzerConnectionStable, so the loss starts a fresh grace period
kill "$SINK_PID"; wait "$SINK_PID" 2>/dev/null || true
sleep 0.5
[[ "$(readyz_code)" == 200 ]] && pass "grace set: 200 within the grace period" || bad "within grace: $(readyz)"
for _ in $(seq 25); do [[ "$(readyz)" == *"analyzer: stream down"* ]] && break; sleep 0.2; done
[[ "$(readyz)" == *"analyzer: stream down"* ]] && pass "grace set: 503 after the grace period" || bad "after grace: $(readyz)"
ip netns exec "$NS_SCR" "$SINK_BIN" 127.0.0.1:59999 "$CMD_FIFO" >>"$SINK_LOG" 2>&1 &
SINK_PID=$!
for _ in $(seq 100); do [[ "$(readyz)" == ready ]] && break; sleep 0.2; done
[[ "$(readyz)" == ready ]] && pass "grace set: /readyz recovers when the analyzer returns" || bad "after analyzer restart: $(readyz)"
stop_collector
start_collector

log "fail open on crash"
stop_collector
scr ip link show out0 | grep -q xdp && bad "xdp_scrub still attached after kill -9" || pass "XDP detached with the process"
http_ok "http://$DST4:8080/" && pass "kernel keeps forwarding without the collector" || bad "traffic stopped after collector crash"

log "drain on clean shutdown"
start_collector -readyz-drain 3s
kill -TERM "$COLLECTOR_PID"
sleep 1
code=$(scr curl -s -o /dev/null -w '%{http_code}' "http://$METRICS/readyz" || true)
attached=$(scr ip link show out0 | grep -c xdp || true)
[[ "$code" == 503 && "$attached" -ge 1 ]] && pass "/readyz 503 while still attached" || bad "during drain: readyz=$code attached=$attached"
wait "$COLLECTOR_PID" 2>/dev/null || true
COLLECTOR_PID=""
scr ip link show out0 | grep -q xdp && bad "still attached after shutdown" || pass "detached after drain"

echo
if [[ $FAILURES -gt 0 ]]; then
  die "$FAILURES check(s) failed"
fi
log "all scrub checks passed"
