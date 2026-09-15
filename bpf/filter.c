/* eBPF filter entry point */
//go:build ignore


#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h> // Required for parsing TCP headers
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VPN_PORT 51820 // Standard WireGuard UDP Port
#define DOT_PORT 853   // DNS over TLS TCP Port

// Dynamic BPF Map for blocked AI subnets/IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // Destination IPv4 Address
    __type(value, __u8);  // 1 = Blocked
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parse IPv4 Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
        
    // 3. Drop packets matching dynamic IP blocklist
    __u32 dst_ip = ip->daddr;
    __u8 *is_blocked = bpf_map_lookup_elem(&blocked_ips, &dst_ip);
    if (is_blocked && *is_blocked == 1) {
        return XDP_DROP; 
    }

    // 4. Parse UDP Header (Block WireGuard)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        if (udp->dest == bpf_htons(VPN_PORT)) {
            return XDP_DROP;
        }
    } 
    // 5. Parse TCP Header (Block DNS over TLS)
    else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if (tcp->dest == bpf_htons(DOT_PORT)) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
