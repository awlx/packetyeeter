//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h> 
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Configuration ---
// Increased map sizes for handling large-scale DDoS
#define BLOCK_MAP_SIZE 3000000
#define HANDSHAKES_MAP_SIZE 500000
// Bad-flags scanners tracked for telemetry. LRU so a spoofed-source scan flood
// evicts the oldest entry instead of failing inserts (E2BIG) once full, which
// would otherwise blind the userspace signal pipeline to every new scanner.
#define BADFLAGS_MAP_SIZE 100000

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

// --- Data Structures ---

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct tcp_session_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct tcp_session_key_v6 {
    struct in6_addr saddr;
    struct in6_addr daddr;
    __u16 sport;
    __u16 dport;
};

struct handshake_status {
    __u64 begin_time;
    __u64 synack_time;
    __u8 synack_sent;
    __u8 pad[7];
};

struct rate_limit {
    __u64 last_time;
    __u64 count;
};

// Bad TCP flag scan classification, stored alongside the last-seen
// timestamp so userspace can emit a structured SIGNAL_BAD_FLAGS signal
// (with a human-readable reason) instead of just knowing "something bad
// happened from this IP at some point".
#define BAD_FLAGS_NONE     0
#define BAD_FLAGS_SYN_FIN  1
#define BAD_FLAGS_XMAS     2
#define BAD_FLAGS_NULL     3

struct bad_flags_info {
    __u64 last_seen;
    __u32 scan_type;  // one of BAD_FLAGS_*
    __u32 flags_raw;  // raw TCP flag bits (fin,syn,rst,psh,ack,urg,ece,cwr from bit 0)
};

// Structured incident logging: every XDP_DROP decision made by the
// collector's own kernel-space enforcement (as opposed to blocks
// commanded by the analyzer) emits one of these onto the `incidents`
// perf event array, so operators get a per-packet audit trail (source,
// reason, timestamp) instead of only aggregate counters.
#define INCIDENT_BLOCKED_IP   1 // Matched blocked_ips/blocked_ips_v6 (analyzer-issued block)
#define INCIDENT_POLICY_BLOCK 2 // Matched an operator -policy CIDR with action=block
#define INCIDENT_ICMP_RATE    3 // ICMP/ICMPv6 rate limit exceeded
#define INCIDENT_UDP_RATE     4 // UDP rate limit exceeded
#define INCIDENT_UDP_FRAG     5 // Fragmented UDP/IPv6 fragment extension header
#define INCIDENT_BAD_FLAGS    6 // SYN+FIN / Xmas / NULL scan TCP flags

struct incident_event {
    __u64 timestamp;
    __u32 saddr_v4;
    __u8  saddr_v6[16];
    __u8  is_v6;
    __u8  reason;
    __u8  pad[2]; // Explicit padding: keeps sizeof() at 32 bytes with no
                  // compiler-inserted gaps, so the Go-side mirror struct
                  // can be decoded with a plain sequential binary.Read.
};

// Per-CIDR policy engine: lets an operator force a BLOCK or MONITOR
// decision for a whole network range, independent of (and checked before)
// the rest of the detection pipeline. MONITOR forces monitor-mode
// (log-only, never drop) for matching sources even when the collector is
// otherwise enforcing; BLOCK always drops matching sources outright
// (subject to the same global dry-run/monitor override as everything
// else, so operators can dry-run a new policy before it takes effect).
#define POLICY_NONE    0
#define POLICY_BLOCK   1
#define POLICY_MONITOR 2

struct policy_entry {
    __u32 action; // one of POLICY_*
};

struct lpm_key_v4 {
    __u32 prefixlen;
    __u32 data;
};

struct lpm_key_v6 {
    __u32 prefixlen;
    __u8 data[16];
};

// --- Maps (Libbpf style) ---

// Use LRU_HASH to automatically evict old entries if the map fills up during extreme attacks.
// This ensures we never stop blocking NEW attackers just because the map is full.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLOCK_MAP_SIZE);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLOCK_MAP_SIZE);
    __type(key, struct in6_addr);
    __type(value, __u64);
} blocked_ips_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, HANDSHAKES_MAP_SIZE);
    __type(key, struct tcp_session_key);
    __type(value, struct handshake_status);
} pending_handshakes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, HANDSHAKES_MAP_SIZE);
    __type(key, struct tcp_session_key_v6);
    __type(value, struct handshake_status);
} pending_handshakes_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLOCK_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct rate_limit);
} icmp_rates SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLOCK_MAP_SIZE);
    __type(key, struct in6_addr);
    __type(value, struct rate_limit);
} icmp_rates_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLOCK_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct rate_limit);
} udp_rates SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BLOCK_MAP_SIZE);
    __type(key, struct in6_addr);
    __type(value, struct rate_limit);
} udp_rates_v6 SEC(".maps");

// AllowList Maps (LPM Trie)
// Used to prevent blocking of trusted IPs/Subnets
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, __u64); // Value doesn't matter, existence check
} allowlist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v6);
    __type(value, __u64);
} allowlist_v6 SEC(".maps");

// Per-CIDR policy engine maps (see struct policy_entry above).
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, struct policy_entry);
} policy_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v6);
    __type(value, struct policy_entry);
} policy_v6 SEC(".maps");

// Counts packets dropped by an explicit POLICY_BLOCK CIDR rule, keyed by
// source IP, so the collector can surface policy-engine activity even
// though (unlike blocked_ips) these blocks are never reported back from
// the analyzer.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} policy_blocks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct in6_addr);
    __type(value, __u64);
} policy_blocks_v6 SEC(".maps");

// Bad Flags (TCP) - separate because handled by existing logic, but could unify?
// Keeping existing logical to minimize drift for now.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BADFLAGS_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct bad_flags_info);
} bad_flags SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BADFLAGS_MAP_SIZE);
    __type(key, struct in6_addr);
    __type(value, struct bad_flags_info);
} bad_flags_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

// Perf Event Array for Fingerprinting
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Perf Event Array for structured incident logging (see struct
// incident_event above). Kept separate from `events` so userspace can
// decode a single fixed struct layout per ring instead of a discriminated
// union.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} incidents SEC(".maps");

// Metadata struct
struct event_metadata {
    __u8  saddr_v6[16];
    __u32 saddr_v4;
    __u32 rtt_us;
    __u32 seq;         // TCP sequence number for pattern analysis
    __u32 ts_val;      // TCP timestamp value (TSval)
    __u32 ts_ecr;      // TCP timestamp echo reply (TSecr)
    __u16 sport;
    __u16 dport;
    __u16 window;
    __u16 len;
    __u16 mss;         // Maximum segment size (from TCP options)
    __u8  protocol;
    __u8  type;        // 1 = JA4T (SYN), 2 = RTT (ACK), 3 = Connection Pattern
    __u8  is_v6;
    __u8  ttl;
    __u8  tcp_flags;   // Raw TCP flags byte for analysis
    __u8  ipv6_ext_headers; // Count of IPv6 extension headers
    __u8  has_timestamp;    // 1 if TCP timestamp option present
    __u8  entropy_score;    // Payload entropy estimate (0-100)
};

// --- Helpers ---

// Check rate limit. Returns 1 if limit exceeded (block), 0 if OK.
static __always_inline int check_rate_limit(void *map, void *key, __u32 limit, __u64 now) {
    struct rate_limit *rate = bpf_map_lookup_elem(map, key);
    if (rate) {
        if (now - rate->last_time > 1000000000) {
            // New 1s window. A benign race here (two CPUs both resetting, or a
            // reset racing an increment) only mis-counts by ~1 packet at the
            // window boundary, so the reset is left as a plain store.
            rate->last_time = now;
            rate->count = 1;
            return 0;
        } else {
            // The value is shared across CPUs for a given source; a plain
            // read-modify-write loses increments under a same-source flood
            // spread over RX queues, which lets the flood stay under `limit`.
            // Increment atomically and test the post-increment value.
            __u64 count = __sync_fetch_and_add(&rate->count, 1) + 1;
            if (count > limit) {
                return 1;
            }
            return 0;
        }
    } else {
        struct rate_limit new_rate = { .last_time = now, .count = 1 };
        bpf_map_update_elem(map, key, &new_rate, BPF_ANY);
        return 0;
    }
}

static __always_inline int check_tcp_flags(struct tcphdr *tcp) {
    if (tcp->syn && tcp->fin) return BAD_FLAGS_SYN_FIN;
    if (tcp->fin && tcp->urg && tcp->psh) return BAD_FLAGS_XMAS;
    // NULL scan check: all 0.
    // Note: res1, doff, res2 are not flags. We just check the flag bits.
    // Standard flags: fin,syn,rst,psh,ack,urg,ece,cwr
    if (!tcp->syn && !tcp->ack && !tcp->rst && !tcp->fin && !tcp->urg && !tcp->psh) return BAD_FLAGS_NULL;
    return BAD_FLAGS_NONE;
}

static __always_inline __u32 tcp_flags_raw(struct tcphdr *tcp) {
    return (__u32)tcp->fin
        | ((__u32)tcp->syn << 1)
        | ((__u32)tcp->rst << 2)
        | ((__u32)tcp->psh << 3)
        | ((__u32)tcp->ack << 4)
        | ((__u32)tcp->urg << 5)
        | ((__u32)tcp->ece << 6)
        | ((__u32)tcp->cwr << 7);
}

// emit_incident_v4/v6 record a structured incident (source, reason,
// timestamp) onto the `incidents` perf event array for every XDP_DROP
// decision made by the collector's own kernel-space enforcement.
static __always_inline void emit_incident_v4(struct xdp_md *ctx, __u32 saddr, __u8 reason, __u64 now) {
    struct incident_event inc = {};
    inc.timestamp = now;
    inc.saddr_v4 = saddr;
    inc.is_v6 = 0;
    inc.reason = reason;
    bpf_perf_event_output(ctx, &incidents, BPF_F_CURRENT_CPU, &inc, sizeof(inc));
}

static __always_inline void emit_incident_v6(struct xdp_md *ctx, struct in6_addr *saddr, __u8 reason, __u64 now) {
    struct incident_event inc = {};
    inc.timestamp = now;
    __builtin_memcpy(inc.saddr_v6, saddr, 16);
    inc.is_v6 = 1;
    inc.reason = reason;
    bpf_perf_event_output(ctx, &incidents, BPF_F_CURRENT_CPU, &inc, sizeof(inc));
}

// Parse TCP timestamp option
// Returns 1 if timestamp found, 0 otherwise
static __always_inline int parse_tcp_timestamp(struct tcphdr *tcp, void *data_end, __u32 *ts_val, __u32 *ts_ecr) {
    // Initialize outputs
    *ts_val = 0;
    *ts_ecr = 0;

    // Critical: Verify TCP header is within packet bounds before ANY field access
    // The verifier loses context when tcp pointer is passed to this function
    if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
        return 0;
    }

    // TCP header length in bytes
    __u32 tcp_hdr_len = tcp->doff * 4;
    
    // Sanity check: minimum TCP header is 20 bytes
    if (tcp_hdr_len < 20 || tcp_hdr_len > 60) {
        return 0;
    }

    // Options start after fixed 20-byte header
    // Use struct pointer arithmetic for verifier
    __u8 *options = (__u8 *)(tcp + 1);
    
    // Calculate options length (header length - fixed 20 bytes)
    __u32 options_len = tcp_hdr_len - 20;
    
    // CRITICAL: Bounds check - if no options, return early
    if (options_len == 0) {
        return 0;
    }
    
    // Verify we can read at least 1 byte of options
    if (options + 1 > (__u8 *)data_end) {
        return 0;
    }
    
    __u8 *options_end = options + options_len;

    // Ensure options_end doesn't exceed packet bounds
    if (options_end > (__u8 *)data_end) {
        return 0;
    }

    // Parse options with bounded loop for verifier
    // Manual unroll to avoid verifier issues
    int found = 0;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        // Skip if already found
        if (found) {
            continue;
        }
        
        // Bounds checks first
        if (options >= options_end || options + 1 > (__u8 *)data_end) {
            continue;
        }

        __u8 kind = *options;

        // End of options list
        if (kind == 0) {
            continue;
        }

        // NOP (1-byte option)
        if (kind == 1) {
            options++;
            continue;
        }

        // All other options have length field
        if (options + 2 > (__u8 *)data_end) {
            continue;
        }

        __u8 len = *(options + 1);
        
        // Validate length
        if (len < 2) {
            continue;
        }

        // TCP Timestamp option (kind=8, len=10)
        if (kind == 8 && len == 10 && options + 10 <= (__u8 *)data_end) {
            // Read TSval (bytes 2-5)
            *ts_val = bpf_ntohl(*(__u32 *)(options + 2));
            
            // Read TSecr (bytes 6-9)
            *ts_ecr = bpf_ntohl(*(__u32 *)(options + 6));
            
            found = 1;
        }

        // Advance to next option (with bounds check)
        if (len <= 40 && options + len <= options_end) {
            options += len;
        } else {
            break;
        }
    }

    return found;
}

// Simplified payload entropy estimation
// Returns entropy score 0-100 (0=very low, 100=high/uniform)
// This is NOT true Shannon entropy (too complex for eBPF), but a heuristic:
// - Count unique bytes in first N bytes of payload
// - Detect repeated patterns
// - Return approximation suitable for bot detection
static __always_inline __u8 estimate_payload_entropy(void *payload_start, void *data_end, __u16 max_bytes) {
    if (max_bytes > 64) max_bytes = 64; // Limit for eBPF complexity
    
    __u8 *payload = (__u8 *)payload_start;
    __u8 byte_seen[256] = {0}; // Track which byte values appear
    __u16 unique_count = 0;
    __u16 total_count = 0;
    __u8 prev_byte = 0;
    __u16 repeat_count = 0;
    
    // Sample up to max_bytes
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (i >= max_bytes) break;
        if (payload + i >= (__u8 *)data_end) break;
        
        __u8 byte = payload[i];
        total_count++;
        
        // Track unique bytes
        if (byte_seen[byte] == 0) {
            byte_seen[byte] = 1;
            unique_count++;
        }
        
        // Detect repeating bytes (low entropy indicator)
        if (i > 0 && byte == prev_byte) {
            repeat_count++;
        }
        prev_byte = byte;
    }
    
    if (total_count == 0) return 50; // No data, neutral score
    
    // Calculate score based on unique byte ratio and repetition
    // High unique ratio = high entropy
    // Low repetition = higher entropy
    __u32 unique_ratio = (unique_count * 100) / total_count;
    __u32 repeat_ratio = (repeat_count * 100) / total_count;
    
    // Score: unique ratio minus penalty for repetition
    __u32 score = unique_ratio;
    if (repeat_ratio > 50) {
        score = score / 2; // Heavy penalty for >50% repetition
    } else {
        score = score - (repeat_ratio / 2);
    }
    
    if (score > 100) score = 100;
    return (__u8)score;
}

// Count IPv6 extension headers
static __always_inline __u8 count_ipv6_ext_headers(struct ipv6hdr *ip6, void *data_end) {
    __u8 count = 0;
    __u8 next_hdr = ip6->nexthdr;
    void *hdr = (void *)(ip6 + 1);

    // Check for common extension headers
    // 0 = Hop-by-Hop, 43 = Routing, 44 = Fragment, 60 = Destination Options
    #pragma unroll
    for (int i = 0; i < 4; i++) { // Max 4 extension headers
        if (hdr + 8 > data_end) {
            break;
        }

        if (next_hdr == 0 || next_hdr == 43 || next_hdr == 44 || next_hdr == 60) {
            count++;
            // Read next header field (first byte of extension header)
            next_hdr = *(__u8 *)hdr;
            // Skip to next header (simplified - just move 8 bytes)
            hdr += 8;
        } else {
            break;
        }
    }

    return count;
}

// --- XDP Program ---

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *cursor = (void *)(eth + 1);

    // Handle VLANs (up to 3 stacked tags)
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vlan = cursor;
            if ((void *)(vlan + 1) > data_end)
                return XDP_PASS;
            h_proto = vlan->h_vlan_encapsulated_proto;
            cursor = (void *)(vlan + 1);
        } else {
            break;
        }
    }

    __u32 key_monitor = 1;
    __u32 *monitor_mode = bpf_map_lookup_elem(&config_map, &key_monitor);
    int is_monitor = (monitor_mode && *monitor_mode == 1);

    // Frame stacked deeper than the tags we parse: h_proto is still a VLAN
    // ethertype, so neither the IPv4 nor IPv6 branch below would match and the
    // frame would fall through to XDP_PASS uninspected. Fail closed - we cannot
    // see its L3/L4 to enforce on it - while honoring monitor/dry-run mode.
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        if (!is_monitor)
            return XDP_DROP;
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u64 now = bpf_ktime_get_ns();

        // 0. AllowList Check
        struct lpm_key_v4 key_allowed = { .prefixlen = 32, .data = ip->saddr };
        if (bpf_map_lookup_elem(&allowlist_v4, &key_allowed)) {
            return XDP_PASS;
        }

        // 0.5 Policy Engine Check (per-CIDR operator override)
        struct policy_entry *policy = bpf_map_lookup_elem(&policy_v4, &key_allowed);
        if (policy) {
            if (policy->action == POLICY_MONITOR) {
                is_monitor = 1;
            } else if (policy->action == POLICY_BLOCK) {
                __u32 saddr_policy = ip->saddr;
                __u64 *cnt = bpf_map_lookup_elem(&policy_blocks, &saddr_policy);
                if (cnt) {
                    __sync_fetch_and_add(cnt, 1);
                } else {
                    __u64 one = 1;
                    bpf_map_update_elem(&policy_blocks, &saddr_policy, &one, BPF_ANY);
                }
                emit_incident_v4(ctx, saddr_policy, INCIDENT_POLICY_BLOCK, now);
                if (!is_monitor) return XDP_DROP;
            }
        }

        // 1. Blocked IP Check
        // Copy to stack to ensure alignment and safety
        __u32 saddr = ip->saddr;
        __u64 *val = bpf_map_lookup_elem(&blocked_ips, &saddr);
        if (val) {
            __sync_fetch_and_add(val, 1);
            emit_incident_v4(ctx, saddr, INCIDENT_BLOCKED_IP, now);
            if (!is_monitor) return XDP_DROP;
        }

        // 2. ICMP Rate Limit
        if (ip->protocol == IPPROTO_ICMP) {
             __u32 key_icmp_limit = 0;
             __u32 *icmp_thresh = bpf_map_lookup_elem(&config_map, &key_icmp_limit);
             __u32 limit = 100;
             if (icmp_thresh && *icmp_thresh > 0) limit = *icmp_thresh;
             
             // Alert Code 1 = ICMP
             if (check_rate_limit(&icmp_rates, &saddr, limit, now)) {
                 emit_incident_v4(ctx, saddr, INCIDENT_ICMP_RATE, now);
                 if (!is_monitor) return XDP_DROP;
             }
        }
        
        // 3. UDP Checks (Fragment + Rate Limit)
        if (ip->protocol == IPPROTO_UDP) {
             // Block Fragmented UDP
             if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
                 emit_incident_v4(ctx, saddr, INCIDENT_UDP_FRAG, now);
                 if (!is_monitor) return XDP_DROP;
             }
             
             // Rate Limit UDP
             __u32 key_udp_limit = 2;
             __u32 *udp_thresh = bpf_map_lookup_elem(&config_map, &key_udp_limit);
             __u32 limit = 2500; // Default safer UDP limit
             if (udp_thresh && *udp_thresh > 0) limit = *udp_thresh;

             // Alert Code 2 = UDP
             if (check_rate_limit(&udp_rates, &saddr, limit, now)) {
                 emit_incident_v4(ctx, saddr, INCIDENT_UDP_RATE, now);
                 if (!is_monitor) return XDP_DROP;
             }
        }

        // 4. TCP Flag Check
        if (ip->protocol == IPPROTO_TCP) {
             // Standard IP header size for verifier
             struct tcphdr *tcp = (void *)(ip + 1);
             if ((void *)(tcp + 1) > data_end) return XDP_PASS;
             int scan_type = check_tcp_flags(tcp);
             if (scan_type != BAD_FLAGS_NONE) {
                 struct bad_flags_info info = {};
                 info.last_seen = now;
                 info.scan_type = scan_type;
                 info.flags_raw = tcp_flags_raw(tcp);
                 bpf_map_update_elem(&bad_flags, &saddr, &info, BPF_ANY);
                 emit_incident_v4(ctx, saddr, INCIDENT_BAD_FLAGS, now);
                 if (!is_monitor) return XDP_DROP;
             }
        }

    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        
        struct in6_addr saddr = ip6->saddr;
        __u64 now = bpf_ktime_get_ns();

        // 0. AllowList Check
        struct lpm_key_v6 key_allowed;
        key_allowed.prefixlen = 128;
        __builtin_memcpy(key_allowed.data, &saddr, 16);
        if (bpf_map_lookup_elem(&allowlist_v6, &key_allowed)) {
            return XDP_PASS;
        }

        // 0.5 Policy Engine Check (per-CIDR operator override)
        struct policy_entry *policy6 = bpf_map_lookup_elem(&policy_v6, &key_allowed);
        if (policy6) {
            if (policy6->action == POLICY_MONITOR) {
                is_monitor = 1;
            } else if (policy6->action == POLICY_BLOCK) {
                __u64 *cnt6 = bpf_map_lookup_elem(&policy_blocks_v6, &saddr);
                if (cnt6) {
                    __sync_fetch_and_add(cnt6, 1);
                } else {
                    __u64 one = 1;
                    bpf_map_update_elem(&policy_blocks_v6, &saddr, &one, BPF_ANY);
                }
                emit_incident_v6(ctx, &saddr, INCIDENT_POLICY_BLOCK, now);
                if (!is_monitor) return XDP_DROP;
            }
        }

        __u64 *val = bpf_map_lookup_elem(&blocked_ips_v6, &saddr);
        if (val) {
            emit_incident_v6(ctx, &saddr, INCIDENT_BLOCKED_IP, now);
            if (!is_monitor) return XDP_DROP;
        }

        // IPv6 ICMPv6 Rate Limit
        if (ip6->nexthdr == IPPROTO_ICMPV6) {
             __u32 key_icmp_limit = 0; // Shared threshold
             __u32 *icmp_thresh = bpf_map_lookup_elem(&config_map, &key_icmp_limit);
             __u32 limit = 100;
             if (icmp_thresh && *icmp_thresh > 0) limit = *icmp_thresh;

             // Alert Code 1 = ICMP
             if (check_rate_limit(&icmp_rates_v6, &saddr, limit, now)) {
                 emit_incident_v6(ctx, &saddr, INCIDENT_ICMP_RATE, now);
                 if (!is_monitor) return XDP_DROP;
             }
        }

        // IPv6 UDP Checks
        // Note: Fragmentation in IPv6 is an extension header (44). 
        // For simple UDP flood protection, we check if nexthdr is UDP.
        if (ip6->nexthdr == IPPROTO_UDP) {
             __u32 key_udp_limit = 2; // Shared threshold
             __u32 *udp_thresh = bpf_map_lookup_elem(&config_map, &key_udp_limit);
             __u32 limit = 2500;
             if (udp_thresh && *udp_thresh > 0) limit = *udp_thresh;

             // Alert Code 2 = UDP
             if (check_rate_limit(&udp_rates_v6, &saddr, limit, now)) {
                 emit_incident_v6(ctx, &saddr, INCIDENT_UDP_RATE, now);
                 if (!is_monitor) return XDP_DROP;
             }
        }
        // Block IPv6 Fragments
        if (ip6->nexthdr == 44) {
            // It is a fragment.
            emit_incident_v6(ctx, &saddr, INCIDENT_UDP_FRAG, now);
            if (!is_monitor) return XDP_DROP;
        }

        // IPv6 TCP Flag Check
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) > data_end) return XDP_PASS;
            int scan_type = check_tcp_flags(tcp);
            if (scan_type != BAD_FLAGS_NONE) {
                struct bad_flags_info info = {};
                info.last_seen = now;
                info.scan_type = scan_type;
                info.flags_raw = tcp_flags_raw(tcp);
                bpf_map_update_elem(&bad_flags_v6, &saddr, &info, BPF_ANY);
                emit_incident_v6(ctx, &saddr, INCIDENT_BAD_FLAGS, now);
                if (!is_monitor) return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}

// --- TC Ingress (SYN Monitor) ---

SEC("classifier/ingress")
int tc_ingress_syn_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

        // Standard IP header size for verifier
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        if (tcp->syn && !tcp->ack) {
            struct tcp_session_key key = {};
            key.saddr = ip->saddr;
            key.daddr = ip->daddr;
            key.sport = tcp->source;
            key.dport = tcp->dest;

            // Submit for JA4T Analysis
            __u16 pkt_len = (__u16)(data_end - data);
            
            // Limit capture size to avoid overhead (e.g. 128 bytes usually enough for TCP options)
            __u16 capture_len = pkt_len; 
            if (capture_len > 128) capture_len = 128; 

            __u64 flags = BPF_F_CURRENT_CPU | ((__u64)capture_len << 32);

            // Limited metadata
            struct event_metadata meta = {};
            meta.saddr_v4 = ip->saddr;
            meta.is_v6 = 0;
            meta.sport = tcp->source;
            meta.dport = tcp->dest;
            meta.protocol = IPPROTO_TCP;
            meta.type = 1; // JA4T
            meta.window = bpf_ntohs(tcp->window);
            meta.len = pkt_len; 
            meta.rtt_us = 0;
            meta.ttl = ip->ttl;
            meta.seq = bpf_ntohl(tcp->seq);
            meta.tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | 
                            (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
            
            // MSS parsing disabled for now (eBPF verifier complexity)
            meta.mss = 0;
            
            // TCP timestamp parsing - ENABLED for clock skew detection
            __u32 ts_val = 0, ts_ecr = 0;
            if (parse_tcp_timestamp(tcp, data_end, &ts_val, &ts_ecr)) {
                meta.has_timestamp = 1;
                meta.ts_val = ts_val;
                meta.ts_ecr = ts_ecr;
            } else {
                meta.has_timestamp = 0;
                meta.ts_val = 0;
                meta.ts_ecr = 0;
            }
            
            // IPv6 extension headers (always 0 for IPv4)
            meta.ipv6_ext_headers = 0;

            bpf_perf_event_output(skb, &events, flags, &meta, sizeof(meta));


            struct handshake_status *existing = bpf_map_lookup_elem(&pending_handshakes, &key);
            if (!existing) {
                struct handshake_status status = {};
                status.begin_time = bpf_ktime_get_ns();
                status.synack_sent = 0;
                bpf_map_update_elem(&pending_handshakes, &key, &status, BPF_ANY);
            }
        }
        else if (tcp->ack && !tcp->syn) {
            struct tcp_session_key key = {};
            key.saddr = ip->saddr;
            key.daddr = ip->daddr;
            key.sport = tcp->source;
            key.dport = tcp->dest;
            
            struct handshake_status *existing = bpf_map_lookup_elem(&pending_handshakes, &key);
            if (existing && existing->synack_sent) {
                // Calculate RTT
                if (existing->synack_time > 0) {
                     __u64 now = bpf_ktime_get_ns();
                     if (now > existing->synack_time) {
                         __u64 rtt_ns = now - existing->synack_time;
                         struct event_metadata meta = {};
                         meta.saddr_v4 = ip->saddr;
                         meta.is_v6 = 0;
                         meta.sport = tcp->source;
                         meta.dport = tcp->dest;
                         meta.protocol = IPPROTO_TCP;
                         meta.type = 2; // JA4L / RTT
                         meta.rtt_us = (__u32)(rtt_ns / 1000);
                         meta.ttl = ip->ttl;
                         
                         bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &meta, sizeof(meta));
                     }
                }
                bpf_map_delete_elem(&pending_handshakes, &key);
            }
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return TC_ACT_OK;
        // Skipping ext header check for brevity, similar to before
        if (ip6->nexthdr != IPPROTO_TCP) return TC_ACT_OK; 

        struct tcphdr *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        if (tcp->syn && !tcp->ack) {
            struct tcp_session_key_v6 key = {};
            key.saddr = ip6->saddr;
            key.daddr = ip6->daddr;
            key.sport = tcp->source;
            key.dport = tcp->dest;
            
            // JA4T V6
            __u16 pkt_len = (__u16)(data_end - data);
            __u16 capture_len = pkt_len; 
            if (capture_len > 128) capture_len = 128;
            
            __u64 flags = BPF_F_CURRENT_CPU | ((__u64)capture_len << 32);

            struct event_metadata meta = {};
            // We can't fit v6 saddr in u32 saddr field easily without changing struct. 
            // Reuse saddr as "0" to indicate v6 and let userspace parse from payload? 
            // Or use perf_event's raw data which includes IP header.
            meta.type = 1;
            meta.protocol = IPPROTO_TCP;
            meta.window = bpf_ntohs(tcp->window);
            meta.len = pkt_len;
            meta.rtt_us = 0;
            
            // V6 Handling
            __builtin_memcpy(meta.saddr_v6, &ip6->saddr, 16);
            meta.is_v6 = 1;
            meta.saddr_v4 = 0;
            meta.ttl = ip6->hop_limit;
            meta.seq = bpf_ntohl(tcp->seq);
            meta.tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | 
                            (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
            
            // MSS parsing disabled for now (eBPF verifier complexity)
            meta.mss = 0;
            
            // TCP timestamp parsing - ENABLED for clock skew detection
            __u32 ts_val = 0, ts_ecr = 0;
            if (parse_tcp_timestamp(tcp, data_end, &ts_val, &ts_ecr)) {
                meta.has_timestamp = 1;
                meta.ts_val = ts_val;
                meta.ts_ecr = ts_ecr;
            } else {
                meta.has_timestamp = 0;
                meta.ts_val = 0;
                meta.ts_ecr = 0;
            }
            
            // IPv6 extension header counting disabled (eBPF verifier complexity)
            meta.ipv6_ext_headers = 0;

            bpf_perf_event_output(skb, &events, flags, &meta, sizeof(meta));

            struct handshake_status *existing = bpf_map_lookup_elem(&pending_handshakes_v6, &key);
            if (!existing) {
                struct handshake_status status = {};
                status.begin_time = bpf_ktime_get_ns();
                status.synack_sent = 0;
                bpf_map_update_elem(&pending_handshakes_v6, &key, &status, BPF_ANY);
            }
        }
        else if (tcp->ack && !tcp->syn) {
            struct tcp_session_key_v6 key = {};
            key.saddr = ip6->saddr;
            key.daddr = ip6->daddr;
            key.sport = tcp->source;
            key.dport = tcp->dest;
            
            struct handshake_status *existing = bpf_map_lookup_elem(&pending_handshakes_v6, &key);
            if (existing && existing->synack_sent) {
                 if (existing->synack_time > 0) {
                     __u64 now = bpf_ktime_get_ns();
                     if (now > existing->synack_time) {
                         __u64 rtt_ns = now - existing->synack_time;
                         struct event_metadata meta = {};
                         __builtin_memcpy(meta.saddr_v6, &ip6->saddr, 16);
                         meta.is_v6 = 1; 
                         meta.saddr_v4 = 0;
                         meta.sport = tcp->source;
                         meta.dport = tcp->dest;
                         meta.protocol = IPPROTO_TCP;
                         meta.type = 2; // JA4L / RTT
                         meta.rtt_us = (__u32)(rtt_ns / 1000);
                         meta.ttl = ip6->hop_limit;
                         
                         bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &meta, sizeof(meta));
                     }
                }
                bpf_map_delete_elem(&pending_handshakes_v6, &key);
            }
        }
    }
    return TC_ACT_OK;
}

// --- TC Egress ---

SEC("classifier/egress")
int tc_egress_synack_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

        // Standard IP header size for verifier
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        if (tcp->syn && tcp->ack) {
            struct tcp_session_key key = {};
            key.saddr = ip->daddr; 
            key.daddr = ip->saddr; 
            key.sport = tcp->dest; 
            key.dport = tcp->source; 

            struct handshake_status *existing = bpf_map_lookup_elem(&pending_handshakes, &key);
            if (existing) {
                existing->synack_sent = 1;
                existing->synack_time = bpf_ktime_get_ns();
            }
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return TC_ACT_OK;
        if (ip6->nexthdr != IPPROTO_TCP) return TC_ACT_OK; 

        struct tcphdr *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

        if (tcp->syn && tcp->ack) {
            struct tcp_session_key_v6 key = {};
            key.saddr = ip6->daddr; 
            key.daddr = ip6->saddr; 
            key.sport = tcp->dest; 
            key.dport = tcp->source; 

            struct handshake_status *existing = bpf_map_lookup_elem(&pending_handshakes_v6, &key);
            if (existing) {
                existing->synack_sent = 1;
                existing->synack_time = bpf_ktime_get_ns();
            }
        }
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
