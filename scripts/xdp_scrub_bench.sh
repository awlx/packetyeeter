#!/usr/bin/env bash
# xdp_scrub_bench.sh — informational forwarding benchmark of collector scrub
# mode on veth pairs. Not a pass/fail test: it prints numbers for regression
# comparison. See docs/scrub-throughput.md for what they do and do not mean.
#
#   src ns (trafgen) ──veth── scrub ns (collector) ──veth── dst ns (tc counts + drops)
#
# Scenarios (IPv4, 64-byte UDP payload, 1 forward-only flow):
#   a   no rules, 1 sender CPU
#   b   4096 rules, the destination covered by 32 that all miss as late as
#       possible, 1 sender CPU
#   b2  as b, but the rules miss on their destination port
#   c0  clean UDP only, SYN_CPUS sender CPUs (reference for c1/c2)
#   c1  clean UDP + SYN flood from one fixed 4-tuple (handshake lookup hits)
#   c2  clean UDP + SYN flood from random sources (one LRU insert per SYN);
#       compared with c1, which has the same packet mix
#
# Requires root, the eBPF toolchain, curl, python3, ethtool, bpftool, tc and
# trafgen (netsniff-ng). Run:
#   sudo ./scripts/xdp_scrub_bench.sh
# Tunables: DURATION (s, default 10), REPS (default 3), SYN_CPUS (default 3),
# GEN_CPU_OFFSET (first generator CPU, default 1).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION="${DURATION:-10}"
REPS="${REPS:-3}"
SYN_CPUS="${SYN_CPUS:-3}"
GEN_CPU_OFFSET="${GEN_CPU_OFFSET:-1}"
WARMUP=2
TOKEN="$(printf '%04x' $((RANDOM % 65536)))"
NS_SRC="yeetbsrc_${TOKEN}"; NS_SCR="yeetbscr_${TOKEN}"; NS_DST="yeetbdst_${TOKEN}"
CREATED_NS=()
COLLECTOR_PID=""; SINK_PID=""; GEN_PID=""
WORK="$(mktemp -d /tmp/yeet-scrub-bench.XXXXXX)"
# Private binaries, so a concurrent e2e run's builds are left alone.
COLLECTOR_BIN="$WORK/packetyeeter-collector"
SINK_BIN="$WORK/xdp_veth_sink"
CMD_FIFO="$WORK/cmds"
COLLECTOR_LOG="$WORK/collector.log"
SINK_LOG="$WORK/sink.log"
QUEUES=4

SRC4=10.201.1.2; OUT4=10.201.1.1; IN4=10.201.2.1; DST4=10.201.2.2
SYN_FIXED_SRC=10.201.1.9

log() { printf '\033[1;36m[bench]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# Stops trafgen and waits until all its workers are gone. Deleting a netns
# while a worker still transmits into its veth can leave the worker spinning
# in the kernel for good.
stop_gen() {
  [[ -n "$GEN_PID" ]] || return 0
  kill -TERM -- "-$GEN_PID" 2>/dev/null || true
  for _ in $(seq 50); do
    pgrep -g "$GEN_PID" >/dev/null || break
    sleep 0.1
  done
  kill -KILL -- "-$GEN_PID" 2>/dev/null || true
  for _ in $(seq 100); do
    pgrep -g "$GEN_PID" >/dev/null || { wait "$GEN_PID" 2>/dev/null || true; GEN_PID=""; return 0; }
    sleep 0.1
  done
  return 1
}

cleanup() {
  local gen_ok=1
  stop_gen || gen_ok=0
  [[ -n "$COLLECTOR_PID" ]] && kill -9 "$COLLECTOR_PID" 2>/dev/null || true
  [[ -n "$SINK_PID" ]] && kill "$SINK_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  if (( gen_ok )); then
    for ns in "${CREATED_NS[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
  else
    log "trafgen (pgid $GEN_PID) did not exit; leaving namespaces ${CREATED_NS[*]} in place"
  fi
  rm -f "$CMD_FIFO" "$COLLECTOR_BIN" "$SINK_BIN"
  log "cleaned up (logs in $WORK)"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || die "must run as root: sudo $0"
for t in clang go curl python3 ethtool bpftool ip tc trafgen; do
  command -v "$t" >/dev/null || die "missing $t (Debian/Ubuntu: apt install clang llvm libbpf-dev linux-tools-generic curl python3 ethtool netsniff-ng)"
done
for ns in "$NS_SRC" "$NS_SCR" "$NS_DST"; do
  ! ip netns list | awk '{print $1}' | grep -qx "$ns" || die "netns $ns already exists; re-run"
done
(( GEN_CPU_OFFSET + SYN_CPUS + 1 <= $(nproc) )) \
  || die "GEN_CPU_OFFSET=$GEN_CPU_OFFSET SYN_CPUS=$SYN_CPUS needs at least $((GEN_CPU_OFFSET + SYN_CPUS + 1)) CPUs"
(( SYN_CPUS <= QUEUES )) || die "SYN_CPUS must be <= $QUEUES"

log "building eBPF object, collector and analyzer sink"
# A VM's clock can lag the host that wrote the sources, so make may think the
# object is current.
rm -f "$REPO/pkg/collector/ebpf/c/protector.bpf.o"
make -C "$REPO" bpf >/dev/null
( cd "$REPO" && go build -o "$COLLECTOR_BIN" ./cmd/collector && go build -o "$SINK_BIN" ./scripts/xdp_veth_sink )
# trafgen pins worker i to CPU i and has no option to change that; shift its
# pins by GEN_CPU_OFFSET so CPU0, where housekeeping and IRQs land, stays free.
cat >"$WORK/cpushift.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sched.h>
#include <stdlib.h>

int sched_setaffinity(pid_t pid, size_t size, const cpu_set_t *mask) {
    static int (*real)(pid_t, size_t, const cpu_set_t *);
    if (!real)
        real = (int (*)(pid_t, size_t, const cpu_set_t *))dlsym(RTLD_NEXT, "sched_setaffinity");
    const char *env = getenv("GEN_CPU_OFFSET");
    int off = env ? atoi(env) : 0;
    cpu_set_t shifted;
    CPU_ZERO(&shifted);
    for (int i = 0; i + off < CPU_SETSIZE; i++)
        if (CPU_ISSET_S(i, size, mask))
            CPU_SET(i + off, &shifted);
    return real(pid, sizeof(shifted), &shifted);
}
EOF
clang -shared -fPIC -O2 -o "$WORK/cpushift.so" "$WORK/cpushift.c" -ldl

src() { ip netns exec "$NS_SRC" "$@"; }
scr() { ip netns exec "$NS_SCR" "$@"; }
dst() { ip netns exec "$NS_DST" "$@"; }

log "creating namespaces $NS_SRC, $NS_SCR, $NS_DST"
for ns in "$NS_SRC" "$NS_SCR" "$NS_DST"; do ip netns add "$ns"; CREATED_NS+=("$ns"); done
# One queue per sender CPU, so each sender's XDP run gets its own NAPI context
# instead of contending for one ring.
mq="numtxqueues $QUEUES numrxqueues $QUEUES"
ip link add src0 netns "$NS_SRC" $mq type veth peer name out0 netns "$NS_SCR" $mq
ip link add in0 netns "$NS_SCR" $mq type veth peer name dst0 netns "$NS_DST" $mq
src ip addr add "$SRC4/24" dev src0
scr ip addr add "$OUT4/24" dev out0
scr ip addr add "$IN4/24" dev in0
dst ip addr add "$DST4/24" dev dst0
for ns in "$NS_SRC" "$NS_SCR" "$NS_DST"; do ip -n "$ns" link set lo up; done
src ip link set src0 up; scr ip link set out0 up; scr ip link set in0 up; dst ip link set dst0 up
dst ip route add default via "$IN4"
# Spoofed SYN sources are off-link; the scrub node needs no route back since
# the destination's replies are dropped before they leave it.
scr sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
  net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.out0.rp_filter=0
# XDP_REDIRECT into a veth needs NAPI on the receiving peer.
dst ethtool -K dst0 gro on >/dev/null
# A permanent neighbour keeps every packet on the XDP fast path.
DST_MAC=$(dst cat /sys/class/net/dst0/address)
scr ip neigh replace "$DST4" lladdr "$DST_MAC" dev in0 nud permanent
OUT_MAC=$(scr cat /sys/class/net/out0/address)
SRC_MAC=$(src cat /sys/class/net/src0/address)
# Count and drop at the destination's ingress so its stack does not become the
# bottleneck, and so clean UDP and SYNs are counted separately.
dst tc qdisc add dev dst0 clsact
dst tc filter add dev dst0 ingress pref 1 protocol ip flower ip_proto udp action drop
dst tc filter add dev dst0 ingress pref 2 protocol ip flower ip_proto tcp action drop

mkfifo "$CMD_FIFO"
# Held open read-write so the sink never sees EOF between commands.
exec 3<>"$CMD_FIFO"
# Started with ip netns exec directly, not through scr(): backgrounding a
# shell function makes $! a subshell, and cleanup would leave the process
# (and its preallocated maps) running.
ip netns exec "$NS_SCR" "$SINK_BIN" 127.0.0.1:59999 "$CMD_FIFO" >"$SINK_LOG" 2>&1 &
SINK_PID=$!
sleep 0.5

METRICS=127.0.0.1:2112
ip netns exec "$NS_SCR" "$COLLECTOR_BIN" -mode scrub -i out0 -inside-if in0 -metrics-addr "$METRICS" \
  -socket "" -analyzer-addr 127.0.0.1:59999 >>"$COLLECTOR_LOG" 2>&1 &
COLLECTOR_PID=$!
for _ in $(seq 50); do
  [[ "$(scr curl -s -o /dev/null -w '%{http_code}' "http://$METRICS/readyz" || true)" == 200 ]] && break
  kill -0 "$COLLECTOR_PID" 2>/dev/null || { tail -20 "$COLLECTOR_LOG" >&2; die "collector exited"; }
  sleep 0.2
done
[[ "$(scr curl -s -o /dev/null -w '%{http_code}' "http://$METRICS/readyz" || true)" == 200 ]] || die "collector never became ready"

metric() {
  local name="$1"
  [[ -n "${2:-}" ]] && name="$1{$2}"
  scr curl -s "http://$METRICS/metrics" | awk -v n="$name" '$1 == n {print $2; f=1} END {if (!f) print 0}'
}

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
# The per-source UDP limit (default 2500 pps) would drop a single-source
# benchmark flow; config_map[2] has no flag, so raise it directly.
bpftool map update id "$(scrub_map_id config_map)" key 2 0 0 0 value 0xff 0xff 0xff 0xff

send_rules() {
  local sent
  sent=$(grep -c "^SENT type=COMMAND_SET_RULES collectors=1" "$SINK_LOG" || true)
  printf '{"type":"COMMAND_SET_RULES","rules":%s}\n' "$1" >&3
  for _ in $(seq 100); do
    (( $(grep -c "^SENT type=COMMAND_SET_RULES collectors=1" "$SINK_LOG" || true) > sent )) && return 0
    sleep 0.1
  done
  die "rule delta not delivered to the collector"
}
wait_rules() {
  for _ in $(seq 80); do
    [[ "$(metric packetyeeter_scrub_rules_active 'family="ipv4"')" == "$1" ]] && return 0
    sleep 0.25
  done
  die "rules_active{ipv4}=$(metric packetyeeter_scrub_rules_active 'family="ipv4"'), want $1"
}

# ---- traffic -----------------------------------------------------------------
ETH="eth(da=$OUT_MAC, sa=$SRC_MAC)"
UDP_PKT="{ $ETH, ipv4(saddr=$SRC4, daddr=$DST4, ttl=64), udp(sp=40000, dp=9), fill(0x41, 64) }"
SYN_FIXED="{ $ETH, ipv4(saddr=$SYN_FIXED_SRC, daddr=$DST4, ttl=64), tcp(sp=40001, dp=80, syn, seq=1, win=64240) }"
SYN_RAND="{ $ETH, ipv4(saddr=drnd(), daddr=$DST4, ttl=64), tcp(sp=drnd(), dp=80, syn, seq=drnd(), win=64240) }"
# trafgen sends its packets round-robin on every worker CPU (0..N-1); three
# SYNs per clean datagram make the flood the bulk of the work.
printf '%s\n' "$UDP_PKT" >"$WORK/udp.cfg"
printf '%s\n' "$UDP_PKT" "$SYN_FIXED" "$SYN_FIXED" "$SYN_FIXED" >"$WORK/syn_fixed.cfg"
printf '%s\n' "$UDP_PKT" "$SYN_RAND" "$SYN_RAND" "$SYN_RAND" >"$WORK/syn_rand.cfg"

tc_pkts() { # PREF
  dst tc -s filter show dev dst0 ingress pref "$1" | awk '/Sent/ {print $4; exit}'
}
snapshot() {
  printf '%s %s %s %s %s\n' "$(date +%s.%N)" "$(tc_pkts 1)" "$(tc_pkts 2)" \
    "$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="forward"')" \
    "$(metric packetyeeter_scrub_packets_total 'family="ipv4",verdict="drop"')"
}

# run_once CFG CPUS: sets RUN to "udp_pps syn_pps fwd_pps drop_pps". Not run
# in a subshell, so cleanup always knows the generator's pid.
run_once() {
  # Own process group, so stop_gen can signal trafgen's forked workers too.
  setsid ip netns exec "$NS_SRC" env LD_PRELOAD="$WORK/cpushift.so" GEN_CPU_OFFSET="$GEN_CPU_OFFSET" \
    trafgen -o src0 -i "$1" -P "$2" -C >/dev/null 2>&1 &
  GEN_PID=$!
  sleep "$WARMUP"
  kill -0 "$GEN_PID" 2>/dev/null || die "trafgen exited early"
  [[ "$(ps -o pgid= -p "$GEN_PID" | tr -d ' ')" == "$GEN_PID" ]] || die "trafgen is not in its own process group"
  local cpus
  # Workers only: the idle parent may sit anywhere.
  cpus=$(ps -o pid=,psr= -g "$GEN_PID" | awk -v p="$GEN_PID" '$1 != p {print $2}' | sort -nu | tr '\n' ' ')
  awk -v c="$cpus" -v o="$GEN_CPU_OFFSET" 'BEGIN { n = split(c, a, " "); for (i = 1; i <= n; i++) if (a[i] < o) exit 1 }' \
    || die "trafgen runs on CPUs $cpus, below GEN_CPU_OFFSET=$GEN_CPU_OFFSET; the affinity shim did not take"
  local a b
  a=$(snapshot); sleep "$DURATION"; b=$(snapshot)
  stop_gen || die "trafgen did not exit"
  sleep 1
  RUN=$(awk -v a="$a" -v b="$b" 'BEGIN {
    split(a, x, " "); split(b, y, " "); t = y[1] - x[1]
    printf "%.0f %.0f %.0f %.0f\n", (y[2]-x[2])/t, (y[3]-x[3])/t, (y[4]-x[4])/t, (y[5]-x[5])/t }')
}

declare -A RES
# measure NAME CFG CPUS: stores the per-column median of REPS runs in RES[NAME]
measure() {
  local runs=()
  for i in $(seq "$REPS"); do
    run_once "$2" "$3"
    local r="$RUN"
    log "  $1 run $i: udp_rx=$(cut -d' ' -f1 <<<"$r") syn_rx=$(cut -d' ' -f2 <<<"$r") fwd=$(cut -d' ' -f3 <<<"$r") drop=$(cut -d' ' -f4 <<<"$r") pps"
    runs+=("$r")
  done
  RES[$1]=$(printf '%s\n' "${runs[@]}" | python3 -c '
import statistics, sys
rows = [list(map(float, l.split())) for l in sys.stdin if l.strip()]
print(" ".join("%.0f" % statistics.median(c) for c in zip(*rows)))')
}

# ---- scenarios ---------------------------------------------------------------
log "load: $(cut -d' ' -f1-3 /proc/loadavg); ${REPS}x ${DURATION}s per scenario"

log "a: no rules, 1 CPU"
measure a "$WORK/udp.cfg" 1

log "b: loading 4096 IPv4 rules"
EXPIRES=$(date -u -d '+1 hour' +%FT%TZ)
# 31 rules sit on a covering /16 and 4065 on /32s (one of them the
# destination's), so the destination's entry lists the maximum of 32.
# "worst": every rule lets the packet through the protocol, length, fragment
# and both 8-range port checks and then misses all 8 source prefixes, the most
# work a non-matching rule can cost. "port": UDP rules that miss on a single
# destination port range, a typical attack-signature rule.
gen_rules() { # MODE
  python3 - "$1" "$EXPIRES" "$DST4" "$WORK" <<'EOF'
import json, sys
mode, exp, dst, work = sys.argv[1:5]
def body(rid, prefix, prio):
    r = {"id": rid, "dstPrefix": prefix, "protocols": [17],
         "action": "RULE_ACTION_DROP", "priority": prio, "expiresAt": exp}
    if mode == "worst":
        r.update({"fragment": False, "pktLen": {"from": 20, "to": 1500},
                  "srcPorts": [{"from": 1 + i, "to": 1 + i} for i in range(7)] + [{"from": 1024, "to": 65535}],
                  "dstPorts": [{"from": 100 + i, "to": 100 + i} for i in range(7)] + [{"from": 1, "to": 1023}],
                  "srcPrefixes": [f"192.0.2.{i}/32" for i in range(8)]})
    else:
        r["dstPorts"] = [{"from": 1000 + prio, "to": 1000 + prio}]
    return r
rules = [body(f"c{i}", "10.201.0.0/16", i) for i in range(31)]
rules.append(body("dst", dst + "/32", 100))
n = 0
while len(rules) < 4096:
    rules.append(body(f"r{n}", f"10.201.{16 + (n >> 8)}.{n & 255}/32", 100))
    n += 1
with open(f"{work}/rules_add.json", "w") as f:
    json.dump({"upsert": rules}, f)
with open(f"{work}/rules_del.json", "w") as f:
    json.dump({"remove": [r["id"] for r in rules]}, f)
EOF
}

for mode in worst port; do
  name=b; [[ $mode == port ]] && name=b2
  log "$name: loading 4096 IPv4 rules ($mode case)"
  gen_rules "$mode"
  send_rules "$(cat "$WORK/rules_add.json")"
  wait_rules 4096
  log "$name: 4096 rules, 32 covering $DST4, 1 CPU"
  measure "$name" "$WORK/udp.cfg" 1
  [[ "$(metric packetyeeter_scrub_rule_matches_total 'action="drop"')" == 0 ]] || log "warning: benchmark traffic matched a rule"
  send_rules "$(cat "$WORK/rules_del.json")"
  wait_rules 0
done

log "c0: clean UDP only, $SYN_CPUS CPUs"
measure c0 "$WORK/udp.cfg" "$SYN_CPUS"
log "c1: clean UDP + fixed-tuple SYN flood (1:3), $SYN_CPUS CPUs"
measure c1 "$WORK/syn_fixed.cfg" "$SYN_CPUS"
log "c2: clean UDP + random-source SYN flood (1:3), $SYN_CPUS CPUs"
measure c2 "$WORK/syn_rand.cfg" "$SYN_CPUS"

# ---- report ------------------------------------------------------------------
delta() { awk -v a="$1" -v b="$2" 'BEGIN { if (a > 0) printf "%+.1f%%", (b - a) * 100 / a; else print "n/a" }'; }
col() { cut -d' ' -f"$2" <<<"${RES[$1]}"; }
echo
echo "Kernel $(uname -r), $(nproc) CPUs ($(lscpu 2>/dev/null | awk -F': *' '/^Vendor ID/ {v = $2} /^Model name/ {m = $2} END {print (m != "" && m != "-") ? m : v}'))," \
  "load $(cut -d' ' -f1-3 /proc/loadavg); veth, native XDP, median of ${REPS}x ${DURATION}s"
printf '%-4s %-46s %12s %12s %12s %4s %10s %10s\n' scen description "udp rx pps" "syn rx pps" "fwd pps" ref "fwd delta" "udp delta"
row() { # NAME REF DESCRIPTION
  printf '%-4s %-46s %12s %12s %12s %4s %10s %10s\n' "$1" "$3" "$(col "$1" 1)" "$(col "$1" 2)" "$(col "$1" 3)" "$2" \
    "$( [[ "$1" == "$2" ]] && echo ref || delta "$(col "$2" 3)" "$(col "$1" 3)")" \
    "$( [[ "$1" == "$2" ]] && echo ref || delta "$(col "$2" 1)" "$(col "$1" 1)")"
}
row a  a  "no rules, 1 CPU"
row b  a  "4096 rules, 32 on dst, worst-case miss, 1 CPU"
row b2 a  "4096 rules, 32 on dst, dst-port miss, 1 CPU"
row c0 c0 "clean UDP, $SYN_CPUS CPUs"
row c1 c0 "UDP + fixed-tuple SYN 1:3, $SYN_CPUS CPUs"
# Against c1: same packet mix, so the difference is the LRU inserts.
row c2 c1 "UDP + random-source SYN 1:3, $SYN_CPUS CPUs"
echo "drop verdict pps (should be ~0): a=$(col a 4) b=$(col b 4) b2=$(col b2 4) c0=$(col c0 4) c1=$(col c1 4) c2=$(col c2 4)"
