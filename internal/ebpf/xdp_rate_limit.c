// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IPv4 address
    __type(value, __u64); // Last seen timestamp
} rate_limit_map SEC(".maps");

SEC("xdp")
int xdp_rate_limit(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&rate_limit_map, &src_ip);

    if (last_seen) {
        // If last seen less than 1ms ago, drop packet (very aggressive rate limiting example)
        if (now - *last_seen < 1000000) {
            return XDP_DROP;
        }
    }

    bpf_map_update_elem(&rate_limit_map, &src_ip, &now, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
