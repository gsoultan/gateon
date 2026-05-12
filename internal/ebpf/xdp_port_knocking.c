#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_KNOCK_STEPS 3
#define KNOCK_TIMEOUT_NS 10000000000LL // 10 seconds

struct knock_config {
    __u16 sequence[MAX_KNOCK_STEPS];
    __u16 target_port;
};

struct knock_state {
    __u8 step;
    __u64 last_knock;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // IP address
    __type(value, struct knock_state);
} knock_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct knock_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

SEC("xdp")
int xdp_port_knocking(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u16 dest_port = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dest_port = bpf_ntohs(tcp->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dest_port = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    __u32 zero = 0;
    struct knock_config *conf = bpf_map_lookup_elem(&config_map, &zero);
    if (!conf)
        return XDP_PASS;

    // Check if accessing target port
    if (dest_port == conf->target_port) {
        if (bpf_map_lookup_elem(&allowed_ips, &src_ip))
            return XDP_PASS;
        return XDP_DROP;
    }

    // Check if this is a knock
    int i;
    for (i = 0; i < MAX_KNOCK_STEPS; i++) {
        if (dest_port == conf->sequence[i]) {
            struct knock_state *state = bpf_map_lookup_elem(&knock_states, &src_ip);
            __u64 now = bpf_ktime_get_ns();

            if (!state) {
                if (i == 0) {
                    struct knock_state new_state = { .step = 1, .last_knock = now };
                    bpf_map_update_elem(&knock_states, &src_ip, &new_state, BPF_ANY);
                }
            } else {
                if (now - state->last_knock > KNOCK_TIMEOUT_NS) {
                    bpf_map_delete_elem(&knock_states, &src_ip);
                    if (i == 0) {
                        struct knock_state new_state = { .step = 1, .last_knock = now };
                        bpf_map_update_elem(&knock_states, &src_ip, &new_state, BPF_ANY);
                    }
                    return XDP_DROP;
                }

                if (i == state->step) {
                    state->step++;
                    state->last_knock = now;
                    if (state->step == MAX_KNOCK_STEPS) {
                        __u8 val = 1;
                        bpf_map_update_elem(&allowed_ips, &src_ip, &val, BPF_ANY);
                        bpf_map_delete_elem(&knock_states, &src_ip);
                    }
                } else {
                     // Wrong step, reset
                     bpf_map_delete_elem(&knock_states, &src_ip);
                }
            }
            return XDP_DROP; // Consume the knock packet
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
