//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct backend {
    __u32 ip;
    __u8 eth_addr[ETH_ALEN];
};

// Per-source token bucket. LRU rather than a plain hash: a plain hash fills
// under a spoofed-source flood and then rejects every new key (E2BIG) for the
// life of the program, so no new source could be tracked at all.
struct rl_state {
    __u64 last_ns; // when the bucket was last refilled
    __u64 tokens;  // packets that may still pass before the next refill
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IPv4 address
    __type(value, struct rl_state);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IP
    __type(value, __u64); // Min interval in nanoseconds
} adaptive_limits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 address
    __type(value, __u32); // Drop reason or just a flag
} shunned_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 address
    __type(value, __u32); // SYNs seen since the source last sent anything else
} tcp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // IPv4 address (Management Whitelist)
    __type(value, __u32); 
} mgmt_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);   // Port
    __type(value, __u32); // Flag
} phantom_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IPv4 address
    __type(value, __u64); // Packet count
} ip_telemetry SEC(".maps");

struct knock_state {
    __u32 step;    // next index into knocking_config this source has to hit
    __u32 _pad;
    __u64 last_ns; // time of the previous knock, for the timeout
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IP
    __type(value, struct knock_state);
} knocking_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);   // Step
    __type(value, __u32); // Port
} knocking_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);   // Index
    __type(value, struct backend);
} lb_backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);   // Always 0
    __type(value, __u32); // Count
} lb_backends_count SEC(".maps");

// ---------------------------------------------------------------------------
// IPv6 state. Separate maps rather than one keyed by a mapped address, so the
// IPv4 maps -- and the Go code, tests and dashboard that read them -- stay as
// they are. Blocking and rate limiting are keyed by the /64 an address sits in:
// an IPv6 client is handed a whole /64 and can send from any address in it, so
// a shun or a limit per address is evaded by changing the last 64 bits. The
// allowlist, telemetry, SYN tracking and knocking are per address. The hashes
// that user space fills are allocated per entry, not up front, because on the
// deployment target most of them stay nearly empty.
// ---------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u64);   // source /64: the prefix's eight bytes as they sit in the header
    __type(value, __u32);
} shunned_prefixes6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // source /64
    __type(value, struct rl_state);
} rate_limit_map6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u64);   // source /64
    __type(value, __u64); // min interval in nanoseconds
} adaptive_limits6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct in6_addr);
    __type(value, __u32); // SYNs seen since the source last sent anything else
} tcp_conntrack6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct in6_addr);
    __type(value, __u32);
} mgmt_whitelist6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct in6_addr);
    __type(value, __u64); // packet count
} ip_telemetry6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct in6_addr);
    __type(value, struct knock_state);
} knocking_state6 SEC(".maps");

struct ebpf_config {
    __u32 mgmt_port;
    __u32 enable_knocking;
    __u32 enable_mgmt_whitelist;
    __u32 enable_rate_limit; // the default per-source limit; adaptive_limits entries apply regardless
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ebpf_config);
} global_ebpf_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

#define DROP_REASON_SHUNNED_IP 1
#define DROP_REASON_BLOCKED_COUNTRY 2
#define DROP_REASON_INVALID_PORT_KNOCK 3
#define DROP_REASON_RATE_LIMITED 4
#define DROP_REASON_SYN_FLOOD 5

static __always_inline void count_drop(__u32 reason) {
    __u64 *count = bpf_map_lookup_elem(&drop_stats, &reason);
    if (count) {
        *count += 1;
    }
}

// Default sustained rate when ebpf_config.enable_rate_limit is set: one packet
// per millisecond, 1000 pps. An adaptive_limits entry overrides it per source.
#define RL_DEFAULT_INTERVAL_NS 1000000ULL
// Packets a source may send at once before the sustained rate applies. A TCP
// window is a burst: a limiter with no burst allowance drops the second segment
// of every window and stalls every connection it touches.
#define RL_BURST_PACKETS 64ULL
// Consecutive SYNs, with nothing else from the source in between, before it is
// treated as a SYN flood. A browser opens six connections at once; a flood
// opens thousands.
#define SYN_BURST_LIMIT 64

// token_bucket_exceeded is the per-source token bucket shared by both hooks and
// both address families: one token per interval up to RL_BURST_PACKETS, one
// token per packet. Returns 1 when the packet must be dropped. Without an entry
// in limits nothing is limited unless the operator turned the default limiter
// on; those entries are explicit user-space decisions and always apply.
static __always_inline int token_bucket_exceeded(void *limits, void *states, const void *key,
                                                 int default_enabled) {
    __u64 interval = RL_DEFAULT_INTERVAL_NS;
    __u64 *custom = bpf_map_lookup_elem(limits, key);
    if (custom) {
        interval = *custom;
    } else if (!default_enabled) {
        return 0;
    }
    if (interval == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    struct rl_state *st = bpf_map_lookup_elem(states, key);
    if (!st) {
        struct rl_state fresh = { .last_ns = now, .tokens = RL_BURST_PACKETS - 1 };
        bpf_map_update_elem(states, key, &fresh, BPF_ANY);
        return 0;
    }

    __u64 refill = (now - st->last_ns) / interval;
    if (refill > 0) {
        __u64 tokens = st->tokens + refill;
        st->tokens = tokens > RL_BURST_PACKETS ? RL_BURST_PACKETS : tokens;
        st->last_ns += refill * interval; // carry the remainder forward
    }
    if (st->tokens == 0) return 1;
    st->tokens -= 1;
    return 0;
}

static __always_inline int rate_limit_exceeded(__u32 src_ip, int default_enabled) {
    return token_bucket_exceeded(&adaptive_limits, &rate_limit_map, &src_ip, default_enabled);
}

// rate_limit_exceeded6 limits an IPv6 source by its /64; see shunned_prefixes6.
static __always_inline int rate_limit_exceeded6(__u64 prefix, int default_enabled) {
    return token_bucket_exceeded(&adaptive_limits6, &rate_limit_map6, &prefix, default_enabled);
}

// The fragment-offset bits of iphdr.frag_off (include/net/ip.h, not uapi).
#define IP_FRAG_OFFSET_MASK 0x1FFF
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif
#define TCP_FLAGS_BYTE 13
#define TCP_FLAG_BITS_SYN 0x02
#define TCP_FLAG_BITS_ACK 0x10

// l4_view is what the checks read from the transport header: the TCP or UDP
// destination port -- offset 2 in both -- or 0 when unreadable, and the TCP
// flags byte, or -1 when unreadable.
struct l4_view {
    __u16 dport;
    int flags;
};

// L4_READ_AT fills v from a transport header OFF bytes into the IPv4 header.
// OFF is a literal, so the verifier sees an immediate add; barrier_var stops
// the compiler from merging read_l4's cases back into one computed offset.
#define L4_READ_AT(v, iph, data_end, OFF)                         \
    do {                                                          \
        __u8 *p_ = (__u8 *)(iph) + (OFF);                         \
        barrier_var(p_);                                          \
        if ((void *)(p_ + 4) <= (data_end))                       \
            (v).dport = ((__u16)p_[2] << 8) | p_[3];              \
        if ((void *)(p_ + TCP_FLAGS_BYTE + 1) <= (data_end))      \
            (v).flags = p_[TCP_FLAGS_BYTE];                       \
    } while (0)

// read_l4 reads the transport header once, for every check that needs a port
// or the TCP flags.
//
// IHL, not sizeof(struct iphdr), says where the transport header starts. It
// used to be taken as a fixed 20 bytes in, which is right only for a header
// without options: one option word moved every port-based decision onto bytes
// the sender chose, and the management-port gate let the packet through.
//
// A later fragment carries no transport header at all, so nothing is read from
// it; it cannot be delivered without its first fragment, which is checked. Each
// field needs only its own bytes, because a first fragment may hold as little
// as eight bytes of the header -- asking for a whole TCP header let a SYN split
// that way skip the gate while reassembly delivered it.
//
// The shape is for a loader holding CAP_BPF and CAP_NET_ADMIN but not
// CAP_PERFMON, which is all the gateway asks for. Without CAP_PERFMON the
// verifier's Spectre hardening refuses a register added to a packet pointer and
// a packet pointer compared against NULL, and explores both sides of every
// branch, which took a loop over the option words past its million-instruction
// limit. Hence one case per IHL, each reading at a literal offset. Asking for
// CAP_PERFMON instead would let the gateway load tracing programs that read
// kernel memory, for the sake of a header offset.
static __always_inline struct l4_view read_l4(struct iphdr *iph, void *data_end) {
    struct l4_view v = { .dport = 0, .flags = -1 };
    if (iph->frag_off & bpf_htons(IP_FRAG_OFFSET_MASK))
        return v;
    switch (iph->ihl) {
    case 5:  L4_READ_AT(v, iph, data_end, 20); break;
    case 6:  L4_READ_AT(v, iph, data_end, 24); break;
    case 7:  L4_READ_AT(v, iph, data_end, 28); break;
    case 8:  L4_READ_AT(v, iph, data_end, 32); break;
    case 9:  L4_READ_AT(v, iph, data_end, 36); break;
    case 10: L4_READ_AT(v, iph, data_end, 40); break;
    case 11: L4_READ_AT(v, iph, data_end, 44); break;
    case 12: L4_READ_AT(v, iph, data_end, 48); break;
    case 13: L4_READ_AT(v, iph, data_end, 52); break;
    case 14: L4_READ_AT(v, iph, data_end, 56); break;
    case 15: L4_READ_AT(v, iph, data_end, 60); break;
    }
    return v;
}

// l6_view is read_l6's answer: the fields of l4_view, the final header when it
// was reached, and whether the packet carried a header read_l6 does not walk.
struct l6_view {
    __u16 dport;
    int flags;
    __u8 proto;  // TCP, UDP, ICMPv6, ...: the header the chain ends in
    __u8 opaque; // a header this program does not walk: the port could be anything
};

// L6_FINAL finishes read_l6 for final header nh at literal offset OFF.
#define L6_FINAL(v, nh, ip6, data_end, OFF)                           \
    do {                                                              \
        (v).proto = (nh);                                             \
        if ((nh) == IPPROTO_TCP || (nh) == IPPROTO_UDP)               \
            L4_READ_AT(v, ip6, data_end, OFF);                        \
        else if ((nh) != IPPROTO_ICMPV6 && (nh) != IPPROTO_NONE)      \
            (v).opaque = 1;                                           \
    } while (0)

// read_l6 finds an IPv6 packet's transport header as far as it can without
// walking a header of arbitrary length, which the verifier refuses a loader
// without CAP_PERFMON (see read_l4): straight after the fixed header, after one
// Fragment header, or after one Hop-by-Hop header of the minimum size. That
// last is the shape of an MLD report, which a gate must never catch: without
// MLD, switches stop forwarding the multicast neighbour discovery rides on.
// Anything else is opaque -- the caller knows it cannot see the port.
static __always_inline struct l6_view read_l6(struct ipv6hdr *ip6, void *data_end) {
    struct l6_view v = { .dport = 0, .flags = -1, .proto = 0, .opaque = 0 };
    __u8 nh = ip6->nexthdr;
    if (nh != IPPROTO_FRAGMENT && nh != IPPROTO_HOPOPTS) {
        L6_FINAL(v, nh, ip6, data_end, 40);
        return v;
    }
    __u8 *eh = (__u8 *)(ip6 + 1);
    barrier_var(eh);
    if ((void *)(eh + 8) > data_end) {
        v.opaque = 1;
        return v;
    }
    if (nh == IPPROTO_FRAGMENT) {
        // A later fragment carries no transport header; its first fragment is
        // the one the gates see.
        if ((((__u16)eh[2] << 8) | eh[3]) & 0xFFF8)
            return v;
    } else if (eh[1] != 0) {
        v.opaque = 1;
        return v;
    }
    __u8 inner = eh[0];
    L6_FINAL(v, inner, ip6, data_end, 48);
    return v;
}

#define MAX_KNOCK_STEPS 8
#define KNOCK_TIMEOUT_NS 10000000000LL // 10 seconds between consecutive knocks
// Returned when the packet is neither a knock nor aimed at the management port,
// so the caller carries on with the rest of the pipeline.
#define KNOCK_NOT_HANDLED -1

// port_knock runs for every TCP packet while knocking is enabled: it
// has to see the knocks, and a knock is by definition not addressed to the
// management port. It used to be reached only for management-port packets, so
// the sequence loop below was dead and the port could never be opened.
//
// A knock is always consumed (dropped) -- whether it advanced the sequence,
// restarted it or broke it -- so the knock ports never answer.
//
// states and allowed are the knock-state map and the allowlist of the source's
// address family, and src points at the source address keying both.
static __always_inline int port_knock(void *states, void *allowed, const void *src, __u16 dest_port,
                                      struct ebpf_config *cfg) {
    if (dest_port == cfg->mgmt_port) {
        // Whitelisted, or completed the sequence: pass. Anyone else: drop.
        if (bpf_map_lookup_elem(allowed, src)) return XDP_PASS;
        count_drop(DROP_REASON_INVALID_PORT_KNOCK);
        return XDP_DROP;
    }

    int i;
    for (i = 0; i < MAX_KNOCK_STEPS; i++) {
        __u32 step_idx = i;
        __u32 *expected_port = bpf_map_lookup_elem(&knocking_config, &step_idx);
        if (!expected_port || *expected_port == 0) break;
        if (dest_port != *expected_port) continue;

        __u64 now = bpf_ktime_get_ns();
        struct knock_state *st = bpf_map_lookup_elem(states, src);
        if (st && now - st->last_ns > KNOCK_TIMEOUT_NS) {
            // Too slow: a half-finished sequence does not stay open forever.
            bpf_map_delete_elem(states, src);
            st = NULL;
        }
        if (!st) {
            if (i == 0) {
                struct knock_state fresh = { .step = 1, .last_ns = now };
                bpf_map_update_elem(states, src, &fresh, BPF_ANY);
            }
            return XDP_DROP;
        }
        if (i != st->step) {
            // Out of order: start over from nothing.
            bpf_map_delete_elem(states, src);
            return XDP_DROP;
        }
        st->step += 1;
        st->last_ns = now;
        __u32 next_idx = st->step;
        __u32 *next_port = NULL;
        if (next_idx < MAX_KNOCK_STEPS)
            next_port = bpf_map_lookup_elem(&knocking_config, &next_idx);
        if (!next_port || *next_port == 0) {
            // Sequence complete: open the management port for this source.
            __u32 val = 1;
            bpf_map_update_elem(allowed, src, &val, BPF_ANY);
            bpf_map_delete_elem(states, src);
        }
        return XDP_DROP;
    }

    return KNOCK_NOT_HANDLED;
}

static __always_inline int handle_port_knocking(__u32 src_ip, __u16 dest_port, struct ebpf_config *cfg) {
    return port_knock(&knocking_state, &mgmt_whitelist, &src_ip, dest_port, cfg);
}

static __always_inline int handle_ip_packet(struct xdp_md *ctx, struct ethhdr *eth) {
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

    // Telemetry: Count packets per IP (using LRU to prevent memory exhaustion)
    __u64 *p_count = bpf_map_lookup_elem(&ip_telemetry, &src_ip);
    if (p_count) {
        __sync_fetch_and_add(p_count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&ip_telemetry, &src_ip, &init_count, BPF_ANY);
    }

    // 1. IP Shunning (DDoS Mitigation)
    __u32 *shunned = bpf_map_lookup_elem(&shunned_ips, &src_ip);
    if (shunned) {
        count_drop(DROP_REASON_SHUNNED_IP);
        return XDP_DROP;
    }

    // The transport header, read once for every check below.
    struct l4_view l4 = read_l4(iph, data_end);

    // 2. TCP State Anomaly & SYN Flood Protection
    if (iph->protocol == IPPROTO_TCP) {
        if (l4.flags >= 0) {
            if ((l4.flags & TCP_FLAG_BITS_SYN) && !(l4.flags & TCP_FLAG_BITS_ACK)) {
                // Count SYNs since this source last sent anything else. It used
                // to drop on the second one, which is what a browser opening its
                // parallel connections looks like; only a source that keeps
                // opening connections and never completes one is a flood.
                __u32 *pending = bpf_map_lookup_elem(&tcp_conntrack, &src_ip);
                if (pending) {
                    if (*pending >= SYN_BURST_LIMIT) {
                        count_drop(DROP_REASON_SYN_FLOOD);
                        return XDP_DROP;
                    }
                    __sync_fetch_and_add(pending, 1);
                } else {
                    __u32 one = 1;
                    bpf_map_update_elem(&tcp_conntrack, &src_ip, &one, BPF_ANY);
                }
            } else {
                // On any other packet from this IP, we clear the SYN state for simplicity
                // In a full conntrack we'd track ESTABLISHED
                bpf_map_delete_elem(&tcp_conntrack, &src_ip);
            }
        }
    }

    // 2. Management Protection
    __u32 config_key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&global_ebpf_config, &config_key);
    if (cfg && cfg->mgmt_port > 0 && iph->protocol == IPPROTO_TCP) {
        __u16 dport = l4.dport;
        if (dport) {
            if (cfg->enable_knocking) {
                // Every TCP packet, not only those for the management port:
                // the knocks are precisely the packets that are not for it.
                int v = handle_port_knocking(src_ip, dport, cfg);
                if (v != KNOCK_NOT_HANDLED) return v;
            } else if (cfg->enable_mgmt_whitelist && dport == cfg->mgmt_port) {
                if (bpf_map_lookup_elem(&mgmt_whitelist, &src_ip)) return XDP_PASS;
                count_drop(DROP_REASON_INVALID_PORT_KNOCK);
                return XDP_DROP;
            }
        }
    }

    // TITAN: Phantom Redirection (AF_XDP)
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        __u16 dport = l4.dport;
        if (dport > 0) {
            __u32 port_key = (__u32)dport;
            if (bpf_map_lookup_elem(&phantom_ports, &port_key)) {
                return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);
            }
        }
    }

    // 3. Rate Limiting (Adaptive)
    if (rate_limit_exceeded(src_ip, cfg && cfg->enable_rate_limit)) {
        count_drop(DROP_REASON_RATE_LIMITED);
        return XDP_DROP;
    }

    // 3. Basic Load Balancing (L3/L4)
    // For simplicity, we only balance TCP/UDP traffic and if backends are configured.
    //
    // An entry is only usable if it carries a destination MAC. Rewriting
    // eth->h_dest to 00:00:00:00:00:00 and returning XDP_TX puts the frame back
    // on the wire addressed to nobody, and it is gone -- XDP_TX has no fallback
    // and nothing upstack ever sees the packet. That is what the Go side used
    // to install for every backend, because it has no ARP and no static MAC
    // table to resolve one from; UpdateLoadBalancerBackends now refuses rather
    // than write an unaddressable entry, and this is the same refusal on the
    // kernel side, for an entry written by anything else. Pass the packet up
    // the normal path instead of destroying it.
    __u32 key = 0;
    __u32 *count = bpf_map_lookup_elem(&lb_backends_count, &key);
    if (count && *count > 0) {
        __u32 index = src_ip % (*count);
        struct backend *be = bpf_map_lookup_elem(&lb_backends, &index);
        __u8 mac_bits = 0;
        if (be) {
            for (int i = 0; i < ETH_ALEN; i++) {
                mac_bits |= be->eth_addr[i];
            }
        }
        if (be && mac_bits) {
            // NOTE: this still does not recompute the IPv4 header checksum or
            // the TCP/UDP checksum, both of which cover the destination address
            // being rewritten here. It is reachable only for an entry with a
            // resolved MAC, which nothing installs today; whoever adds MAC
            // resolution has to add both checksum fixups in the same change.
            iph->daddr = be->ip;
            for (int i = 0; i < ETH_ALEN; i++) {
                eth->h_dest[i] = be->eth_addr[i];
            }
            // For XDP_TX to work, we usually need to swap source/dest MAC if we want to send it back.
            // But here we are acting as a gateway/balancer, so we want to forward it.
            return XDP_TX;
        }
    }

    return XDP_PASS;
}

// src_prefix64 is the /64 an IPv6 source sits in, as shunned_prefixes6 and the
// IPv6 rate limiter key it: the address's first eight bytes, unconverted.
static __always_inline __u64 src_prefix64(const struct in6_addr *src) {
    __u64 prefix;
    __builtin_memcpy(&prefix, src, sizeof(prefix));
    return prefix;
}

static __always_inline void count_source6(const struct in6_addr *src) {
    __u64 *count = bpf_map_lookup_elem(&ip_telemetry6, src);
    if (count) {
        __sync_fetch_and_add(count, 1);
        return;
    }
    __u64 one = 1;
    bpf_map_update_elem(&ip_telemetry6, src, &one, BPF_ANY);
}

// syn_flood6 is the IPv4 SYN-burst guard for one IPv6 source.
static __always_inline int syn_flood6(const struct in6_addr *src, int flags) {
    if (!(flags & TCP_FLAG_BITS_SYN) || (flags & TCP_FLAG_BITS_ACK)) {
        bpf_map_delete_elem(&tcp_conntrack6, src);
        return 0;
    }
    __u32 *pending = bpf_map_lookup_elem(&tcp_conntrack6, src);
    if (!pending) {
        __u32 one = 1;
        bpf_map_update_elem(&tcp_conntrack6, src, &one, BPF_ANY);
        return 0;
    }
    if (*pending >= SYN_BURST_LIMIT)
        return 1;
    __sync_fetch_and_add(pending, 1);
    return 0;
}

// mgmt_gate6 is the IPv4 management-port gate, plus a rule for a packet whose
// port read_l6 cannot see: while a gate is on, it is dropped unless its source
// is on the allowlist. It might be addressed to the management port, and a
// header this program does not walk must not be a way around the gate. Returns
// KNOCK_NOT_HANDLED when the gate has no say.
static __always_inline int mgmt_gate6(struct ebpf_config *cfg, const struct in6_addr *src,
                                      const struct l6_view *l6) {
    if (!cfg || cfg->mgmt_port == 0 || !(cfg->enable_knocking || cfg->enable_mgmt_whitelist))
        return KNOCK_NOT_HANDLED;
    if (l6->opaque) {
        if (bpf_map_lookup_elem(&mgmt_whitelist6, src))
            return KNOCK_NOT_HANDLED;
        count_drop(DROP_REASON_INVALID_PORT_KNOCK);
        return XDP_DROP;
    }
    if (l6->proto != IPPROTO_TCP || !l6->dport)
        return KNOCK_NOT_HANDLED;
    if (cfg->enable_knocking)
        return port_knock(&knocking_state6, &mgmt_whitelist6, src, l6->dport, cfg);
    if (l6->dport != cfg->mgmt_port)
        return KNOCK_NOT_HANDLED;
    if (bpf_map_lookup_elem(&mgmt_whitelist6, src))
        return XDP_PASS;
    count_drop(DROP_REASON_INVALID_PORT_KNOCK);
    return XDP_DROP;
}

// handle_ipv6_packet is handle_ip_packet for IPv6, in the same order: count the
// source, the blocklist, the SYN-burst guard, the management gate, the rate
// limiter. Phantom ports and load balancing stay IPv4-only.
static __always_inline int handle_ipv6_packet(struct xdp_md *ctx, struct ethhdr *eth) {
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    struct in6_addr src = ip6->saddr;
    __u64 prefix = src_prefix64(&src);
    count_source6(&src);

    if (bpf_map_lookup_elem(&shunned_prefixes6, &prefix)) {
        count_drop(DROP_REASON_SHUNNED_IP);
        return XDP_DROP;
    }

    struct l6_view l6 = read_l6(ip6, data_end);
    if (l6.proto == IPPROTO_TCP && l6.flags >= 0 && syn_flood6(&src, l6.flags)) {
        count_drop(DROP_REASON_SYN_FLOOD);
        return XDP_DROP;
    }

    __u32 config_key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&global_ebpf_config, &config_key);
    int gate = mgmt_gate6(cfg, &src, &l6);
    if (gate != KNOCK_NOT_HANDLED)
        return gate;

    if (rate_limit_exceeded6(prefix, cfg && cfg->enable_rate_limit)) {
        count_drop(DROP_REASON_RATE_LIMITED);
        return XDP_DROP;
    }
    return XDP_PASS;
}

SEC("xdp")
int xdp_gateon_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        return handle_ip_packet(ctx, eth);
    }
    if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        return handle_ipv6_packet(ctx, eth);
    }

    return XDP_PASS;
}

// ---------------------------------------------------------------------------
// TC (clsact) ingress path
// ---------------------------------------------------------------------------
//
// Same filtering decisions as the XDP program, at the hook that actually works
// on a virtualized NIC. Native XDP is unavailable on most EC2 instances (the
// ENA driver rejects it above a page-sized MTU and when the driver is using
// every queue), and generic/SKB XDP is a trap: it runs at roughly this point in
// the stack anyway, but additionally demands 256 bytes of XDP_PACKET_HEADROOM
// — calling pskb_expand_head() when the skb lacks it — and linearizes non-linear
// skbs. The clsact ingress hook has neither requirement, so for a pure drop
// decision it is strictly cheaper than generic XDP and works at MTU 9001.
//
// It deliberately implements only the drop decisions. Port knocking mutates
// per-IP state and load balancing needs XDP_TX/redirect; both stay XDP-only
// rather than being half-ported into a hook that cannot express them.
//
// These read the SAME maps as the XDP program, so ShunIP, SetAdaptiveRateLimit
// and UpdateManagementWhitelist all keep working with no Go-side change
// regardless of which hook is attached.

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

// tc_filter_ipv4 returns TC_ACT_SHOT when the packet must be dropped. Split out
// of the entry point to keep each function within the verifier's comfort zone.
// Order: the management allowlist, then the blocklists, then the rate limiter.
static __always_inline int tc_filter_ipv4(struct iphdr *iph, void *data_end) {
    __u32 src_ip = iph->saddr;

    // A listed source short-circuits before any drop check, so an operator can
    // never lock themselves out with a bad rule. Anyone else is held to the
    // allowlist on the management port, as the XDP program does. That second
    // arm used to be missing -- this program never read a port -- so on TC the
    // setting admitted every address while the dashboard said it admitted none.
    __u32 config_key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&global_ebpf_config, &config_key);
    if (cfg && cfg->enable_mgmt_whitelist) {
        if (bpf_map_lookup_elem(&mgmt_whitelist, &src_ip)) return TC_ACT_OK;
        if (cfg->mgmt_port > 0 && iph->protocol == IPPROTO_TCP &&
            read_l4(iph, data_end).dport == cfg->mgmt_port) {
            count_drop(DROP_REASON_INVALID_PORT_KNOCK);
            return TC_ACT_SHOT;
        }
    }

    // Telemetry, LRU-backed so a spoofed-source flood cannot grow it without
    // bound. Same map the XDP path feeds, so GetTopIPs is hook-agnostic.
    __u64 *p_count = bpf_map_lookup_elem(&ip_telemetry, &src_ip);
    if (p_count) {
        __sync_fetch_and_add(p_count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&ip_telemetry, &src_ip, &init_count, BPF_ANY);
    }

    if (bpf_map_lookup_elem(&shunned_ips, &src_ip)) {
        count_drop(DROP_REASON_SHUNNED_IP);
        return TC_ACT_SHOT;
    }

    if (rate_limit_exceeded(src_ip, cfg && cfg->enable_rate_limit)) {
        count_drop(DROP_REASON_RATE_LIMITED);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

// tc_filter_ipv6 is tc_filter_ipv4 for IPv6, with mgmt_gate6's rule for a
// header read_l6 does not walk. Like the IPv4 path it does no port knocking.
static __always_inline int tc_filter_ipv6(struct ipv6hdr *ip6, void *data_end) {
    struct in6_addr src = ip6->saddr;
    __u64 prefix = src_prefix64(&src);

    __u32 config_key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&global_ebpf_config, &config_key);
    if (cfg && cfg->enable_mgmt_whitelist) {
        if (bpf_map_lookup_elem(&mgmt_whitelist6, &src)) return TC_ACT_OK;
        if (cfg->mgmt_port > 0) {
            struct l6_view l6 = read_l6(ip6, data_end);
            if (l6.opaque || (l6.proto == IPPROTO_TCP && l6.dport == cfg->mgmt_port)) {
                count_drop(DROP_REASON_INVALID_PORT_KNOCK);
                return TC_ACT_SHOT;
            }
        }
    }

    count_source6(&src);

    if (bpf_map_lookup_elem(&shunned_prefixes6, &prefix)) {
        count_drop(DROP_REASON_SHUNNED_IP);
        return TC_ACT_SHOT;
    }
    if (rate_limit_exceeded6(prefix, cfg && cfg->enable_rate_limit)) {
        count_drop(DROP_REASON_RATE_LIMITED);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

SEC("tc")
int tc_gateon_ingress(struct __sk_buff *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;
        return tc_filter_ipv4(iph, data_end);
    }
    if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;
        return tc_filter_ipv6(ip6, data_end);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
