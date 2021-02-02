/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* <linux/bpf.h> must precede <bpf/bpf_helpers.h> due to integer types
 * in bpf helpers signatures.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

volatile __u8 is_allow_list = 1;

/* Map containing the network interfaces indexes.
 * The interpretation of the map depends on the value of is_allow_list.
 */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u32);
        __type(value, __u8);
        __uint(max_entries, 1); /* Set from user space with bpf_map__resize helper */
} ifaces_map SEC(".maps");

#define DROP 0
#define PASS 1

static inline int restrict_network_interfaces_impl(struct __sk_buff *sk) {
        __u32 zero = 0, ifindex;
        __u8 *lookup_result;

        ifindex = sk->ifindex;
        lookup_result = bpf_map_lookup_elem(&ifaces_map, &ifindex);
        if (is_allow_list) {
            /* allow-list: let the packet pass if iface in the list */
            if (lookup_result)
                return PASS;
        } else {
            /* deny-list: let the packet pass if iface *not* in the list */
            if (!lookup_result)
                    return PASS;
        }

        return DROP;
}

SEC("cgroup_skb/egress")
int restrict_network_interfaces_egress(struct __sk_buff *sk)
{
        return restrict_network_interfaces_impl(sk);
}

SEC("cgroup_skb/ingress")
int restrict_network_interfaces_ingress(struct __sk_buff *sk)
{
        return restrict_network_interfaces_impl(sk);
}

char _license[] SEC("license") = "LGPL-2.1-or-later";
