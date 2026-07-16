#!/usr/bin/env bash
# xdp_veth_test.sh — local XDP end-to-end test on a virtual veth pair.
#
# Purpose: exercise the collector's XDP datapath without touching a real NIC,
# and specifically validate the IPv6 ICMP/UDP flood gap flagged in review
# (kernel populates icmp_rates_v6 / udp_rates_v6, but the Go userspace never
# reads them, so v6 floods produce no analyzer signals).
#
# Requires root (XDP attach + veth + bpftool) and the eBPF toolchain. Run:
#   sudo ./scripts/xdp_veth_test.sh
#
# It is self-contained and idempotent: it sets up, tests, prints a verdict,
# and tears everything down (even on failure, via the trap).
set -euo pipefail

# ---- config ----------------------------------------------------------------
NS="yeetns"
VETH_HOST="yeet0"        # collector attaches XDP here
VETH_PEER="yeet1"        # traffic source, lives in the netns
HOST_V4="10.123.0.1"; PEER_V4="10.123.0.2"
HOST_V6="fd00:dead::1";  PEER_V6="fd00:dead::2"
PREFIX4=24; PREFIX6=64
FLOOD_SECS=6
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECTOR_BIN="$REPO/bin/packetyeeter-collector"
SINK_BIN="$REPO/bin/xdp_veth_sink"
UDPFLOOD_BIN="$REPO/bin/xdp_veth_udpflood"
COLLECTOR_LOG="$(mktemp /tmp/yeet-collector.XXXXXX.log)"
SINK_LOG="$(mktemp /tmp/yeet-sink.XXXXXX.log)"
SINK_ADDR="127.0.0.1:59999"
COLLECTOR_PID=""
SINK_PID=""

log()  { printf '\033[1;36m[test]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[fail]\033[0m %s\n' "$*"; exit 1; }

if [[ $EUID -ne 0 ]]; then fail "must run as root (XDP attach + veth). Use: sudo $0"; fi

cleanup() {
  set +e
  [[ -n "$COLLECTOR_PID" ]] && kill "$COLLECTOR_PID" 2>/dev/null && wait "$COLLECTOR_PID" 2>/dev/null
  [[ -n "$SINK_PID" ]] && kill "$SINK_PID" 2>/dev/null && wait "$SINK_PID" 2>/dev/null
  ip link del "$VETH_HOST" 2>/dev/null           # deleting one end removes the pair
  ip netns del "$NS" 2>/dev/null
  log "cleaned up (logs kept: collector=$COLLECTOR_LOG sink=$SINK_LOG)"
}
trap cleanup EXIT

# ---- 0. toolchain ----------------------------------------------------------
# Hard requirements to build + attach; bpftool is optional (corroboration only).
need=()
for t in clang ip nping go; do command -v "$t" >/dev/null || need+=("$t"); done
[[ -f /usr/include/bpf/bpf_helpers.h ]] || need+=("libbpf-headers")
if [[ ${#need[@]} -gt 0 ]]; then
  warn "missing: ${need[*]}"
  warn "install on Fedora/Nobara: sudo dnf install -y clang llvm libbpf-devel bpftool nmap kernel-headers"
  fail "toolchain incomplete"
fi
HAVE_BPFTOOL=0; command -v bpftool >/dev/null && HAVE_BPFTOOL=1 || \
  warn "bpftool not found — map-dump corroboration skipped; verdict uses the collector log"

# ---- 1. build --------------------------------------------------------------
# Compile the eBPF object via make, but build the Go binary with `go build`
# directly: the `make collector` target regenerates protobuf via buf, which
# isn't needed here (generated files are committed).
log "building eBPF object + collector + signal sink"
make -C "$REPO" bpf >/dev/null
( cd "$REPO" && go build -o "$COLLECTOR_BIN" ./cmd/collector )
( cd "$REPO" && go build -o "$SINK_BIN" ./scripts/xdp_veth_sink )
( cd "$REPO" && go build -o "$UDPFLOOD_BIN" ./scripts/xdp_veth_udpflood )
[[ -x "$COLLECTOR_BIN" ]] || fail "collector binary not built at $COLLECTOR_BIN"
[[ -x "$SINK_BIN" ]] || fail "sink binary not built at $SINK_BIN"
[[ -x "$UDPFLOOD_BIN" ]] || fail "udpflood binary not built at $UDPFLOOD_BIN"

# ---- 2. veth pair + addresses ---------------------------------------------
log "creating veth pair $VETH_HOST <-> $VETH_PEER (peer in netns $NS)"
ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
ip link set "$VETH_PEER" netns "$NS"

ip addr add "$HOST_V4/$PREFIX4" dev "$VETH_HOST"
ip -6 addr add "$HOST_V6/$PREFIX6" dev "$VETH_HOST" nodad
ip link set "$VETH_HOST" up

ip netns exec "$NS" ip addr add "$PEER_V4/$PREFIX4" dev "$VETH_PEER"
ip netns exec "$NS" ip -6 addr add "$PEER_V6/$PREFIX6" dev "$VETH_PEER" nodad
ip netns exec "$NS" ip link set "$VETH_PEER" up
ip netns exec "$NS" ip link set lo up

# Static IPv6 neighbor entries both directions so unicast v6 egresses without
# relying on Neighbor Discovery (nping/ping otherwise stall on ND in the netns).
HMAC=$(cat "/sys/class/net/$VETH_HOST/address")
PMAC=$(ip netns exec "$NS" cat "/sys/class/net/$VETH_PEER/address")
ip -6 neigh replace "$PEER_V6" lladdr "$PMAC" dev "$VETH_HOST"
ip netns exec "$NS" ip -6 neigh replace "$HOST_V6" lladdr "$HMAC" dev "$VETH_PEER"
sleep 1

# ---- 3. run collector (attaches XDP to $VETH_HOST) -------------------------
# No analyzer needed: the collector loads XDP and polls maps regardless of
# whether the analyzer stream connects. Dry-run so nothing is enforced.
# The sink is a throwaway analyzer that logs every signal it receives, with
# its IP family — that's how we prove IPv6 flood signals reach the analyzer
# (the collector's own "Sent … flood signals" log can't tell v4 from v6).
log "starting signal sink on $SINK_ADDR"
"$SINK_BIN" "$SINK_ADDR" >"$SINK_LOG" 2>&1 &
SINK_PID=$!
sleep 1
kill -0 "$SINK_PID" 2>/dev/null || { cat "$SINK_LOG"; fail "sink exited early"; }

# -v surfaces the per-poll debug counters; -dry-run so nothing is enforced.
log "starting collector on $VETH_HOST (dry-run, verbose) -> sink"
"$COLLECTOR_BIN" -i "$VETH_HOST" -dry-run -v -analyzer-addr "$SINK_ADDR" \
  -poll-interval 1s -socket "" -spoe-port 0 -haproxy-port 0 >"$COLLECTOR_LOG" 2>&1 &
COLLECTOR_PID=$!
sleep 3
kill -0 "$COLLECTOR_PID" 2>/dev/null || { cat "$COLLECTOR_LOG"; fail "collector exited early"; }
grep -q 'loaded and attached' "$COLLECTOR_LOG" || warn "no attach confirmation in log yet"

dump_map() { # entry count for a map by name, or "n/a" without bpftool
  [[ "$HAVE_BPFTOOL" -eq 1 ]] || { echo "n/a"; return; }
  bpftool map dump name "$1" 2>/dev/null | grep -c '"key"\|key:' || true
}

# ---- 4. flood: IPv4 + IPv6, ICMP + UDP ------------------------------------
# minFloodPPS in the collector is 1000; nping at --rate 5000 for a few seconds
# clears that comfortably. Source from the peer netns toward the host addrs.
# ICMP: ping -f floods via the kernel stack (reliable source/ND selection);
# ~200k pps on a veth, far above the collector's 1000-pps flood threshold.
# nping's raw v6 path can't auto-pick a source in a netns, so it's not used.
PINGCOUNT=400000
icmp_flood() { # af target
  local six=(); [[ "$1" == 6 ]] && six=(-6)
  timeout $((FLOOD_SECS+4)) ip netns exec "$NS" \
    ping "${six[@]}" -f -c "$PINGCOUNT" "$2" >/dev/null 2>&1 || true
}
# UDP: kernel-stack blaster (handles v6 source/route that nping can't).
udp_flood() { # net target
  ip netns exec "$NS" "$UDPFLOOD_BIN" "$1" "$2" 9999 "$FLOOD_SECS" >/dev/null 2>&1 || true
}
log "flooding ICMPv4"; icmp_flood 4 "$HOST_V4"
log "flooding ICMPv6"; icmp_flood 6 "$HOST_V6"
log "flooding UDPv4";  udp_flood udp4 "$HOST_V4"
log "flooding UDPv6";  udp_flood udp6 "$HOST_V6"
sleep 2   # let the collector poll the maps at least once

# ---- 5. verdict ------------------------------------------------------------
echo
log "=== eBPF map population (kernel datapath ground truth) ==="
for m in icmp_rates icmp_rates_v6 udp_rates udp_rates_v6; do
  printf '  %-16s entries=%s\n' "$m" "$(dump_map "$m")"
done

echo
log "=== flood signals received by the analyzer sink (by IP family) ==="
# Signal IDs are family-tagged: icmp-/udp- (v4) vs icmp6-/udp6- (v6).
v4_sig=$(grep -cE 'SIGNAL .*id=(icmp|udp)-' "$SINK_LOG" || true)
v6_sig=$(grep -cE 'SIGNAL .*id=(icmp6|udp6)-' "$SINK_LOG" || true)
printf '  IPv4 flood signals received: %s\n' "$v4_sig"
printf '  IPv6 flood signals received: %s\n' "$v6_sig"
grep -m4 -E 'SIGNAL .*id=(icmp6|udp6)-' "$SINK_LOG" | sed 's/^/    /' || true

echo
num() { [[ "$1" =~ ^[0-9]+$ ]] && echo "$1" || echo 0; }
icmp_v6_map=$(dump_map icmp_rates_v6); udp_v6_map=$(dump_map udp_rates_v6)
v6_map_total=$(( $(num "$icmp_v6_map") + $(num "$udp_v6_map") ))
log "=== verdict ==="
printf '  v6 rate-map entries (kernel): icmp_rates_v6=%s udp_rates_v6=%s\n' \
  "$icmp_v6_map" "$udp_v6_map"
if [[ "$v6_map_total" -eq 0 ]]; then
  warn "INCONCLUSIVE: the kernel v6 rate maps stayed empty, so no v6 flood"
  warn "reached the datapath this run. Re-run; check veth v6 addressing/carrier."
elif [[ "$(num "$v6_sig")" -gt 0 ]]; then
  log "PASS: the kernel saw the IPv6 flood AND the analyzer received"
  log "$v6_sig IPv6 flood signal(s) — the v6 read path works end-to-end."
else
  warn "FAIL: kernel v6 rate maps populated (total=$v6_map_total) but the analyzer"
  warn "received 0 IPv6 flood signals — the v6 read path is missing/broken."
fi
echo
log "done"
