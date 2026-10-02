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

log()  { printf '\033[1;36m[test]\033[0m %s\n' "$*"; }
pass() { printf '\033[1;32m[pass]\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*"; exit 1; }

cleanup() {
  [[ -n "$COLLECTOR_PID" ]] && kill -9 "$COLLECTOR_PID" 2>/dev/null || true
  [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" 2>/dev/null || true
  [[ -n "$SINK_PID" ]] && kill "$SINK_PID" 2>/dev/null || true
  for ns in "${CREATED_NS[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -f "$UDP_OUT"
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
start_collector() {
  ip netns exec "$NS_SCR" "$COLLECTOR_BIN" -mode scrub -i out0 -inside-if in0 -metrics-addr "$METRICS" \
    -socket "" -analyzer-addr 127.0.0.1:1 -policy "$POLICY4/32=block" "$@" >>"$COLLECTOR_LOG" 2>&1 &
  COLLECTOR_PID=$!
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
ip netns exec "$NS_SCR" "$SINK_BIN" 127.0.0.1:59999 >"$SINK_LOG" 2>&1 &
SINK_PID=$!
sleep 0.5
start_collector -analyzer-addr 127.0.0.1:59999 -handshake-timeout 1s
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
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
for pair in sys.argv[3:]:
    flags, ttl = (int(x, 0) for x in pair.split(":"))
    tcp = struct.pack("!HHIIBBHHH", 40001, 80, 1000, 1, 5 << 4, flags, 64240, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, ttl, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    sock.sendto(ip + tcp, (dst, 0))' "$@"
}
raw_tcp "$SLOWACK4" "$HOLE4" 0x02:64 0x10:1
raw_tcp "$RSTACK4" "$HOLE4" 0x02:64 0x14:64
reported() { grep -q "type=SIGNAL_INCOMPLETE_HANDSHAKE .*ip=$1\$" "$SINK_LOG"; }
for _ in $(seq 30); do reported "$HS4" && reported "$HS6" && break; sleep 0.2; done
sleep 2 # two more polls, so an expired entry for a completed handshake would have surfaced
reported "$HS4" && pass "unanswered IPv4 SYN reported as incomplete handshake" || bad "no incomplete handshake signal for $HS4"
reported "$HS6" && pass "unanswered IPv6 SYN reported as incomplete handshake" || bad "no incomplete handshake signal for $HS6"
reported "$SRC4" || reported "$SRC6" && bad "completed handshake reported as incomplete" || pass "completed handshakes not reported"
reported "$TTL1_4" && bad "SYN the node did not forward was reported" || pass "SYNs left to the kernel not reported"
reported "$SLOWACK4" && bad "handshake whose ACK took the kernel path was reported" || pass "ACKs left to the kernel still complete a handshake"
reported "$RSTACK4" && pass "RST|ACK does not count as a completed handshake" || bad "RST|ACK closed the handshake"

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

log "monitor mode"
stop_collector
start_collector -dry-run
http_ok --interface "$POLICY4" "http://$DST4:8080/" && pass "monitor mode forwards a policy-blocked source" || bad "monitor mode dropped traffic"
[[ "$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="drop"')" == 0 ]] \
  && pass "monitor mode dropped nothing" || bad "drop{ipv4} non-zero in monitor mode"

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
