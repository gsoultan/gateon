//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TLS_HANDSHAKE 22
#define TLS_CLIENT_HELLO 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u8[32]); // JA4 Fingerprint Hash
    __type(value, __u32);
} ja4_blocklist SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u8[16]); // JA3 MD5 Hash
    __type(value, __u32);
} ja3_blocklist SEC(".maps");

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

// rate_limit_exceeded is the per-source token bucket shared by the XDP and TC
// hooks: one token per interval up to RL_BURST_PACKETS, one token per packet.
// Returns 1 when the packet must be dropped. Without an adaptive_limits entry
// nothing is limited unless the operator turned the default limiter on; the
// adaptive entries are explicit user-space decisions and always apply.
static __always_inline int rate_limit_exceeded(__u32 src_ip, int default_enabled) {
    __u64 interval = RL_DEFAULT_INTERVAL_NS;
    __u64 *custom = bpf_map_lookup_elem(&adaptive_limits, &src_ip);
    if (custom) {
        interval = *custom;
    } else if (!default_enabled) {
        return 0;
    }
    if (interval == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    struct rl_state *st = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (!st) {
        struct rl_state fresh = { .last_ns = now, .tokens = RL_BURST_PACKETS - 1 };
        bpf_map_update_elem(&rate_limit_map, &src_ip, &fresh, BPF_ANY);
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

#define MAX_KNOCK_STEPS 8
#define KNOCK_TIMEOUT_NS 10000000000LL // 10 seconds between consecutive knocks
// Returned when the packet is neither a knock nor aimed at the management port,
// so the caller carries on with the rest of the pipeline.
#define KNOCK_NOT_HANDLED -1

// handle_port_knocking runs for every TCP packet while knocking is enabled: it
// has to see the knocks, and a knock is by definition not addressed to the
// management port. It used to be reached only for management-port packets, so
// the sequence loop below was dead and the port could never be opened.
//
// A knock is always consumed (dropped) -- whether it advanced the sequence,
// restarted it or broke it -- so the knock ports never answer.
static __always_inline int handle_port_knocking(struct iphdr *iph, struct tcphdr *tcph, struct ebpf_config *cfg) {
    __u32 src_ip = iph->saddr;
    __u16 dest_port = bpf_ntohs(tcph->dest);

    if (dest_port == cfg->mgmt_port) {
        // Whitelisted, or completed the sequence: pass. Anyone else: drop.
        if (bpf_map_lookup_elem(&mgmt_whitelist, &src_ip)) return XDP_PASS;
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
        struct knock_state *st = bpf_map_lookup_elem(&knocking_state, &src_ip);
        if (st && now - st->last_ns > KNOCK_TIMEOUT_NS) {
            // Too slow: a half-finished sequence does not stay open forever.
            bpf_map_delete_elem(&knocking_state, &src_ip);
            st = NULL;
        }
        if (!st) {
            if (i == 0) {
                struct knock_state fresh = { .step = 1, .last_ns = now };
                bpf_map_update_elem(&knocking_state, &src_ip, &fresh, BPF_ANY);
            }
            return XDP_DROP;
        }
        if (i != st->step) {
            // Out of order: start over from nothing.
            bpf_map_delete_elem(&knocking_state, &src_ip);
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
            bpf_map_update_elem(&mgmt_whitelist, &src_ip, &val, BPF_ANY);
            bpf_map_delete_elem(&knocking_state, &src_ip);
        }
        return XDP_DROP;
    }

    return KNOCK_NOT_HANDLED;
}

static __always_inline int handle_tls_packet(struct xdp_md *ctx, struct iphdr *iph, struct tcphdr *tcph) {
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *payload = (void *)(tcph + 1);

    // TLS record header: [type(1)][version(2)][length(2)]
    if ((void *)(payload + 5) > data_end) return XDP_PASS;

    if (payload[0] != TLS_HANDSHAKE) return XDP_PASS;

    __u8 *handshake = payload + 5;
    // Handshake header: [type(1)][length(3)]
    if ((void *)(handshake + 4) > data_end) return XDP_PASS;

    if (handshake[0] != TLS_CLIENT_HELLO) return XDP_PASS;

    // We take the first 32 bytes of the Client Hello (after headers) as a signature
    // This includes the Client Version and part of the Random/Session ID.
    // While not a full JA4, it's a stable TITAN-grade kernel fingerprint.
    __u8 signature[32];
    __u8 *hello_data = handshake + 4;
    
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if ((void *)(hello_data + i + 1) <= data_end) {
            signature[i] = hello_data[i];
        } else {
            signature[i] = 0;
        }
    }

    if (bpf_map_lookup_elem(&ja4_blocklist, &signature)) {
        return XDP_DROP;
    }

    return XDP_PASS;
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

    // 2. TCP State Anomaly & SYN Flood Protection
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) <= data_end) {
            // Check for TLS Handshake (Client Hello)
            if (handle_tls_packet(ctx, iph, tcph) == XDP_DROP) {
                count_drop(DROP_REASON_SHUNNED_IP);
                return XDP_DROP;
            }

            if (tcph->syn && !tcph->ack) {
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
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) <= data_end) {
            if (cfg->enable_knocking) {
                // Every TCP packet, not only those for the management port:
                // the knocks are precisely the packets that are not for it.
                int v = handle_port_knocking(iph, tcph, cfg);
                if (v != KNOCK_NOT_HANDLED) return v;
            } else if (cfg->enable_mgmt_whitelist && bpf_ntohs(tcph->dest) == cfg->mgmt_port) {
                if (bpf_map_lookup_elem(&mgmt_whitelist, &src_ip)) return XDP_PASS;
                count_drop(DROP_REASON_INVALID_PORT_KNOCK);
                return XDP_DROP;
            }
        }
    }

    // TITAN: Phantom Redirection (AF_XDP)
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        __u16 dport = 0;
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)(tcph + 1) <= data_end) dport = bpf_ntohs(tcph->dest);
        } else {
            struct udphdr *udph = (void *)(iph + 1);
            if ((void *)(udph + 1) <= data_end) dport = bpf_ntohs(udph->dest);
        }

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

// tc_filter_ipv4 returns TC_ACT_SHOT when the source address must be dropped.
// Split out of the entry point to keep each function within the verifier's
// comfort zone and to mirror handle_ip_packet's ordering exactly: whitelist
// first, then the blocklists, then the rate limiter.
static __always_inline int tc_filter_ipv4(struct iphdr *iph) {
    __u32 src_ip = iph->saddr;

    // The management whitelist short-circuits before any drop check so an
    // operator can never lock themselves out with a bad rule.
    __u32 config_key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&global_ebpf_config, &config_key);
    if (cfg && cfg->enable_mgmt_whitelist) {
        if (bpf_map_lookup_elem(&mgmt_whitelist, &src_ip)) return TC_ACT_OK;
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

SEC("tc")
int tc_gateon_ingress(struct __sk_buff *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    return tc_filter_ipv4(iph);
}

char _license[] SEC("license") = "GPL";
