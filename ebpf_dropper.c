/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF Dropper"
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#include <linux/ptrace.h>

#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>

#define IP_TCP 	6
#define ETH_HLEN 14



#define SEC(NAME) __attribute__((section(NAME), used))
#define PIN_GLOBAL_NS		2
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

/* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};


struct bpf_elf_map SEC("maps") map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .size_key = sizeof(int),
        .size_value = sizeof(__u32),
        .pinning = PIN_GLOBAL_NS,
        .max_elem = 2,
};

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);			\
			})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

#define FIN 1
#define SYN 2
#define RST 1 << 2
#define PSH 1 << 3
#define ACK 1 << 4
#define URG 1 << 5
#define ECE 1 << 6
#define CWR 1 << 7

#define PASS TC_ACT_OK
#define DROP TC_ACT_SHOT

// returns DROP is the specified substr is at the end of the payload of the current TCP segment
// retuens PASS otherwise
inline int drop_if_substr_at_the_end(char substr[], int len, struct __sk_buff *skb)
{
	__u8 off = ((__u8) load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq) + 4) & 0xF0) >> 4;
	int header_size = off*4;
	int packet_len = skb -> len - (ETH_HLEN + sizeof(struct iphdr) + header_size);
	int i;
	for(i = 0 ; i < len ; i++) {
		char byte = load_byte(skb, skb -> len - 2 - i);
		if(byte != substr[len - 1 - i])
			return PASS;
	}
	return DROP;
}

// drops if all the TCP flags in set are set and all the TCP flags in unset are unset
inline int drop_on_flags(__u8 set, __u8 unset, struct __sk_buff *skb) {
	__u8 flags = (__u8) load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq) + 4 + 1);
	__u8 set_ok = (flags & set) == set; // true when all the bits sets in set are also set in flags
	__u8 unset_ok = ~((flags & unset) | (flags | unset)) == unset; // true when all the bits sets in unset are unset in flags
	if (!set_ok || unset_ok) {
		return PASS;
	}
	return DROP;
}

// returns the TCP flags if the socket as a 8 bits unsigned integer
inline __u8 get_tcp_flags(struct __sk_buff *skb) {
	return (__u8) load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq) + 4 + 1);
}

// returns DROP if a == DROP or if b == DROP
// returns PASS otherwise
inline int OR(int a, int b) {
	return a == DROP || b == DROP ? DROP : PASS;
}

// returns DROP if a == DROP and if b == DROP
// returns PASS otherwise
inline int AND(int a, int b) {
	return a == DROP && b == DROP ? DROP : PASS; 
}

// returns the IP dest address as a 32 bits unsigned integer
inline __u32 get_daddr(struct __sk_buff *skb) {
        struct iphdr *iphdr = (struct iphdr *) skb + ETH_HLEN;
        ////// LOAD IP ADDR BYTE PER BYTE
        __u32 b1 = ((__u32) load_byte(skb, ETH_HLEN + offsetof(struct iphdr, daddr)) << 24);
        __u32 b2 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, daddr) + 1) << 16;
        __u32 b3 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, daddr) + 2) << 8;
        __u32 b4 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, daddr) + 3);
        ////// END LOAD IP ADDR BYTE PER BYTE 
	return be32_to_cpu(b1 + b2 + b3 + b4);
}

// drops the packets indicated by the f function, only once per TCP connection: the state is reset
// each time a segment with the SYN flag is set
inline int drop_only_once(struct __sk_buff *skb, int (*f)(struct __sk_buff *)) {
	__u32 *seen;
	int key = 0, key2 = 1;
        seen = bpf_map_lookup_elem(&map, &key);
        if(!seen) {
                __u32 val = 0;
                if(bpf_map_update_elem(&map, &key, &val, BPF_NOEXIST))
                        return TC_ACT_OK;
        }
        seen = bpf_map_lookup_elem(&map, &key);
        if(!seen)
                return TC_ACT_OK;
        
        if((get_tcp_flags(skb) & SYN) != 0) {
                __u32 val = 0;
                *seen = 0;
                bpf_debug("RESET SEEN\n");
                bpf_map_update_elem(&map, &key, &val, BPF_EXIST);
                bpf_map_update_elem(&map, &key2, &val, BPF_ANY);
        }

	if(!*seen && (*f)(skb) == DROP) {
		bpf_debug("DROP\n");
		__u32 daddr = get_daddr(skb);
        	__u32 val = 1;
                *seen = 1;
                bpf_map_update_elem(&map, &key, &val, BPF_EXIST);
                bpf_map_update_elem(&map, &key2, &daddr, BPF_ANY);
		return DROP;
	}
	return PASS;
}

// user defined decision function
// returns DROP when a packet must be dropped
// returns PASS otherwise
inline int decision_function(struct __sk_buff *skb) {
	// to be completed by the user
	return AND(drop_on_flags(PSH, 0, skb), drop_if_substr_at_the_end("DROPME", 6, skb));
}

// modified by the user to wrap the decision function with other functions
// returns DROP when a packet must be dropped
// returns PASS otherwise
SEC("action") int handle_ingress(struct __sk_buff *skb)
{
	// to be completed by the user
	return drop_only_once(skb, &decision_function);
}

char _license[] SEC("license") = "GPL";
