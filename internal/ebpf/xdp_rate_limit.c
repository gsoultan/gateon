// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct backend {
    __u32 ip;
    __u8 eth_addr[ETH_ALEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IPv4 address
    __type(value, __u64); // Last seen timestamp
} rate_limit_map SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 address
    __type(value, __u32); // State: 0=None, 1=SYN_SENT, 2=ESTABLISHED
} tcp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // IPv4 address (Management Whitelist)
    __type(value, __u32); 
} mgmt_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Country Code (Simplified)
    __type(value, __u32);
} country_block_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IP
    __type(value, __u32); // Current step in sequence
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

static __always_inline void count_drop(__u32 reason) {
    __u64 *count = bpf_map_lookup_elem(&drop_stats, &reason);
    if (count) {
        *count += 1;
    }
}

#define MAX_KNOCK_STEPS 8
#define KNOCK_TIMEOUT_NS 10000000000LL // 10 seconds

static __always_inline int handle_port_knocking(struct xdp_md *ctx, struct iphdr *iph, struct tcphdr *tcph, struct ebpf_config *cfg) {
    void *data_end = (void *)(long)ctx->data_end;
    __u32 src_ip = iph->saddr;
    __u16 dest_port = bpf_ntohs(tcph->dest);

    // If knocking is disabled, pass
    if (!cfg->enable_knocking) return XDP_PASS;

    // Check if accessing target port (mgmt_port)
    if (dest_port == cfg->mgmt_port) {
        // If IP is already allowed (whitelisted or solved knock), pass
        if (bpf_map_lookup_elem(&mgmt_whitelist, &src_ip)) return XDP_PASS;
        
        count_drop(DROP_REASON_INVALID_PORT_KNOCK);
        return XDP_DROP;
    }

    // Check if this port is part of the sequence
    int i;
    for (i = 0; i < MAX_KNOCK_STEPS; i++) {
        __u32 step_idx = i;
        __u32 *expected_port = bpf_map_lookup_elem(&knocking_config, &step_idx);
        if (!expected_port || *expected_port == 0) break;

        if (dest_port == *expected_port) {
            __u32 *current_step = bpf_map_lookup_elem(&knocking_state, &src_ip);
            __u64 now = bpf_ktime_get_ns();
            
            // We use rate_limit_map to track last knock time for timeout (reuse map or use a new one)
            // For now, just focus on the sequence.
            
            if (!current_step) {
                if (i == 0) {
                    __u32 initial_step = 1;
                    bpf_map_update_elem(&knocking_state, &src_ip, &initial_step, BPF_ANY);
                    return XDP_DROP; // Consume knock
                }
            } else {
                if (i == *current_step) {
                    *current_step += 1;
                    
                    // Check if sequence complete
                    __u32 next_step_idx = *current_step;
                    __u32 *next_port = bpf_map_lookup_elem(&knocking_config, &next_step_idx);
                    if (!next_port || *next_port == 0) {
                        // Sequence complete! Add to whitelist for a limited time (or until manual removal)
                        __u32 val = 1;
                        bpf_map_update_elem(&mgmt_whitelist, &src_ip, &val, BPF_ANY);
                        bpf_map_delete_elem(&knocking_state, &src_ip);
                    }
                    return XDP_DROP; // Consume knock
                } else {
                    // Wrong port in sequence, reset
                    bpf_map_delete_elem(&knocking_state, &src_ip);
                }
            }
        }
    }

    return XDP_PASS;
}

static __always_inline int handle_ip_packet(struct xdp_md *ctx, struct ethhdr *eth) {
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

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
            if (tcph->syn && !tcph->ack) {
                // Tracking SYN starts. If already has a SYN state without ACK, could be a flood.
                __u32 *state = bpf_map_lookup_elem(&tcp_conntrack, &src_ip);
                if (state && *state == 1) {
                    // Possible SYN flood from this IP
                    return XDP_DROP;
                }
                __u32 syn_state = 1;
                bpf_map_update_elem(&tcp_conntrack, &src_ip, &syn_state, BPF_ANY);
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
    if (cfg && cfg->mgmt_port > 0) {
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)(tcph + 1) <= data_end) {
                if (bpf_ntohs(tcph->dest) == cfg->mgmt_port) {
                    // Check whitelist
                    if (cfg->enable_mgmt_whitelist) {
                        __u32 *allowed = bpf_map_lookup_elem(&mgmt_whitelist, &src_ip);
                        if (!allowed) {
                            return handle_port_knocking(ctx, iph, tcph, cfg);
                        }
                    } else if (cfg->enable_knocking) {
                         return handle_port_knocking(ctx, iph, tcph, cfg);
                    }
                }
            }
        }
    }

    // 3. Rate Limiting
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (last_seen) {
        if (now - *last_seen < 1000000) { // 1ms
            return XDP_DROP;
        }
    }
    bpf_map_update_elem(&rate_limit_map, &src_ip, &now, BPF_ANY);

    // 3. Basic Load Balancing (L3/L4)
    // For simplicity, we only balance TCP/UDP traffic and if backends are configured.
    __u32 key = 0;
    __u32 *count = bpf_map_lookup_elem(&lb_backends_count, &key);
    if (count && *count > 0) {
        __u32 index = src_ip % (*count);
        struct backend *be = bpf_map_lookup_elem(&lb_backends, &index);
        if (be) {
            // Rewrite destination IP and MAC
            // In a real scenario, we'd also need to update the checksums or use hardware offload.
            // and potentially handle the source MAC (setting it to the interface MAC).
            iph->daddr = be->ip;
            // eth->h_dest would be be->eth_addr
            // This is a simplified L3 redirect.
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

char _license[] SEC("license") = "GPL";
