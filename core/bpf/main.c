//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// ─────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_AH 51
#define IPPROTO_DSTOPTS 60

#define MAX_SCAN_PORTS 32
#define EVENT_SAMPLE_N 16

// ─────────────────────────────────────────────
// STRUCTS
// ─────────────────────────────────────────────

struct event_t {
    __u64 ts;
    __u32 src_ip;
    __u32 dst_ip;
    struct in6_addr src_ip6;
    struct in6_addr dst_ip6;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  action;   // 0=allow, 1=drop
    __u8  reason;
};

struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

struct lpm_key6 {
    __u32 prefixlen;
    struct in6_addr ip;
};

struct scan_state {
    __u16 ports[MAX_SCAN_PORTS];
    __u8  count;
};

struct drop_totals {
    __u64 packets;
    __u64 bytes;
};

// ─────────────────────────────────────────────
// MAPS
// ─────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} ban_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct in6_addr);
    __type(value, __u8);
} ban_map_v6 SEC(".maps");

// Exact-source ban drops only. Two fixed slots prevent traffic-controlled
// cardinality growth; per-CPU values avoid contended packet-path atomics.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct drop_totals);
} ban_drop_totals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_cidr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __type(key, struct lpm_key6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_cidr_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct scan_state);
} scan_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} event_sample_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} event_sample_rate SEC(".maps");

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

static __always_inline int is_ipv4_whitelisted(__u32 ip) {
    struct lpm_key key = { .prefixlen = 32, .ip = ip };
    __u8 *allowed = bpf_map_lookup_elem(&whitelist_cidr, &key);
    return allowed != 0;
}

static __always_inline int is_ipv6_whitelisted(struct in6_addr *ip6) {
    struct lpm_key6 key = { .prefixlen = 128, .ip = *ip6 };
    __u8 *allowed = bpf_map_lookup_elem(&whitelist_cidr_v6, &key);
    return allowed != 0;
}

static __always_inline int is_banned(__u32 ip) {
    __u8 *flag = bpf_map_lookup_elem(&ban_map, &ip);
    return flag != 0;
}

static __always_inline int is_banned_v6(struct in6_addr *ip6) {
    __u8 *flag = bpf_map_lookup_elem(&ban_map_v6, ip6);
    return flag != 0;
}

static __always_inline void count_ban_drop(__u32 family_slot, __u64 bytes) {
    struct drop_totals *totals = bpf_map_lookup_elem(&ban_drop_totals, &family_slot);
    if (!totals) return;
    totals->packets++;
    totals->bytes += bytes;
}

static __always_inline void record_scan(__u32 ip, __u16 port) {
    struct scan_state *state = bpf_map_lookup_elem(&scan_counter, &ip);
    if (!state) {
        struct scan_state new_state = {};
        new_state.ports[0] = port;
        new_state.count = 1;
        bpf_map_update_elem(&scan_counter, &ip, &new_state, BPF_ANY);
        return;
    }

    #pragma unroll
    for (int i = 0; i < MAX_SCAN_PORTS; i++) {
        if (state->ports[i] == port)
            return;
    }

    if (state->count < MAX_SCAN_PORTS) {
        state->ports[state->count++] = port;
    }
}

static __always_inline void emit_event(struct xdp_md *ctx, __u32 sip, __u32 dip,
                                       __u16 sport, __u16 dport, __u8 proto, __u8 action, __u8 reason) {
    struct event_t *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->ts = bpf_ktime_get_ns();
    e->src_ip = sip;
    e->dst_ip = dip;
    __builtin_memset(&e->src_ip6, 0, sizeof(e->src_ip6));
    __builtin_memset(&e->dst_ip6, 0, sizeof(e->dst_ip6));
    e->src_port = sport;
    e->dst_port = dport;
    e->proto = proto;
    e->action = action;
    e->reason = reason;

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_event_v6(struct xdp_md *ctx, struct in6_addr *sip, struct in6_addr *dip,
                                          __u16 sport, __u16 dport, __u8 proto, __u8 action, __u8 reason) {
    struct event_t *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->ts = bpf_ktime_get_ns();
    e->src_ip = 0;
    e->dst_ip = 0;
    if (sip) e->src_ip6 = *sip;
    if (dip) e->dst_ip6 = *dip;
    e->src_port = sport;
    e->dst_port = dport;
    e->proto = proto;
    e->action = action;
    e->reason = reason;

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int should_emit_allow(void) {
    __u32 key = 0;
    __u32 *cnt = bpf_map_lookup_elem(&event_sample_counter, &key);
    __u32 *rate = bpf_map_lookup_elem(&event_sample_rate, &key);
    __u32 sample_n = EVENT_SAMPLE_N;
    if (rate && *rate > 0)
        sample_n = *rate;
    if (!cnt) return 1;
    __u32 v = (*cnt)++;
    return (v % sample_n) == 0;
}

// ─────────────────────────────────────────────
// MAIN XDP PROGRAM
// ─────────────────────────────────────────────

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // IPv4 Path
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u32 ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(*ip))
            return XDP_PASS;
        if ((void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;

        __u32 src_ip = ip->saddr;

        // Whitelist bypass
        if (is_ipv4_whitelisted(src_ip))
            return XDP_PASS;

        // Ban check
        if (is_banned(src_ip)) {
            count_ban_drop(0, (__u64)((unsigned char *)data_end - (unsigned char *)data));
            emit_event(ctx, src_ip, ip->daddr, 0, 0, ip->protocol, 1, 1);
            return XDP_DROP;
        }

        // Scan detection
        __u16 dport = 0;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)((unsigned char *)ip + ip_hdr_len);
            if ((void *)(tcp + 1) <= data_end)
                dport = bpf_ntohs(tcp->dest);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)((unsigned char *)ip + ip_hdr_len);
            if ((void *)(udp + 1) <= data_end)
                dport = bpf_ntohs(udp->dest);
        }

        record_scan(src_ip, dport);
        if (should_emit_allow()) {
            emit_event(ctx, src_ip, ip->daddr, 0, dport, ip->protocol, 0, 0);
        }

        return XDP_PASS;
    }

    // IPv6 Path (basic)
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        if (is_ipv6_whitelisted(&ip6->saddr))
            return XDP_PASS;

        if (is_banned_v6(&ip6->saddr)) {
            count_ban_drop(1, (__u64)((unsigned char *)data_end - (unsigned char *)data));
            emit_event_v6(ctx, &ip6->saddr, &ip6->daddr, 0, 0, ip6->nexthdr, 1, 1);
            return XDP_DROP;
        }

        __u16 dport6 = 0;
        __u8 proto6 = ip6->nexthdr;
        unsigned char *cur = (unsigned char *)(ip6 + 1);

        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if (proto6 == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *)cur;
                if ((unsigned char *)(tcp + 1) > (unsigned char *)data_end)
                    break;
                dport6 = bpf_ntohs(tcp->dest);
                break;
            } else if (proto6 == IPPROTO_UDP) {
                struct udphdr *udp = (struct udphdr *)cur;
                if ((unsigned char *)(udp + 1) > (unsigned char *)data_end)
                    break;
                dport6 = bpf_ntohs(udp->dest);
                break;
            } else if (proto6 == IPPROTO_HOPOPTS || proto6 == IPPROTO_ROUTING ||
                       proto6 == IPPROTO_DSTOPTS || proto6 == IPPROTO_AH ||
                       proto6 == IPPROTO_FRAGMENT) {
                if (cur + 2 > (unsigned char *)data_end)
                    break;
                __u8 next = cur[0];
                __u8 len = cur[1];
                __u32 adv = 0;
                if (proto6 == IPPROTO_FRAGMENT) {
                    adv = 8;
                } else if (proto6 == IPPROTO_AH) {
                    adv = (len + 2) * 4;
                } else {
                    adv = (len + 1) * 8;
                }
                if (adv == 0 || cur + adv > (unsigned char *)data_end)
                    break;
                cur += adv;
                proto6 = next;
                continue;
            }
            break;
        }

        if (should_emit_allow()) {
            emit_event_v6(ctx, &ip6->saddr, &ip6->daddr, 0, dport6, proto6, 0, 0);
        }
    }

    return XDP_PASS;
}
