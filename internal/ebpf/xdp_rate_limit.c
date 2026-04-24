// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

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

static __always_inline int handle_ip_packet(struct xdp_md *ctx, struct ethhdr *eth) {
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

    // 1. IP Shunning (DDoS Mitigation)
    __u32 *shunned = bpf_map_lookup_elem(&shunned_ips, &src_ip);
    if (shunned) {
        return XDP_DROP;
    }

    // 2. Rate Limiting
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
