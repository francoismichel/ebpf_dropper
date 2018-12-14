/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF Dropper"
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>

#define IP_TCP 	6
#define ETH_HLEN 14



#define SEC(NAME) __attribute__((section(NAME), used))
#define PIN_GLOBAL_NS		2
#define PIN_NONE			0
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};
//
///* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
    unsigned char   h_dest[ETH_ALEN];
    unsigned char   h_source[ETH_ALEN];
    unsigned short  h_proto;
};


struct bpf_elf_map SEC("maps") map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .size_key = sizeof(int),
        .size_value = sizeof(__u32),
        .pinning = PIN_NONE,
        .max_elem = 2,
};

typedef enum state {
    // 0 is reserved value
            GOOD = 1,
    BAD = 2,
} gemodel_state;


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

#define PASS TC_ACT_OK
#define DROP TC_ACT_SHOT

#define NUMARGS(...)  (sizeof((int[]){__VA_ARGS__})/sizeof(int))
#define DROP_IF_ALL_DROP(...) (all_drop_f((int[]){__VA_ARGS__}, NUMARGS(__VA_ARGS__)) ? DROP : PASS)
#define ALL_DROP(...) all_drop_f((int[]){__VA_ARGS__}, NUMARGS(__VA_ARGS__))

#define UDP 0x11

#define PROBA_PRECISION 5 // number of digits in the decimal part

//#define PROBA_percents 5 // loss_percentage
#define PROBA_percents_times_100 ((uint32_t) (PROBA_percents*100))
#define GEMODEL_P_PERCENTS_TIMES_100 ((uint32_t) (GEMODEL_P_PERCENTS*100))
#define GEMODEL_R_PERCENTS_TIMES_100 ((uint32_t) (GEMODEL_R_PERCENTS*100))
#define GEMODEL_K_PERCENTS_TIMES_100 ((uint32_t) (GEMODEL_K_PERCENTS*100))
#define GEMODEL_H_PERCENTS_TIMES_100 ((uint32_t) (GEMODEL_H_PERCENTS*100))
//#define SEED 42
//#define IP1_TO_DROP 0
//#define IP2_TO_DROP 0
//#define PORT_TO_WATCH 6121

static int pow10[8] = {
        1, 10, 100, 1000, 10000,
        100000, 1000000, 10000000
};


__attribute__((always_inline)) uint32_t get_random_u32(uint32_t *state)
{
    return *state = ((uint64_t)*state * 48271u) % 0x7fffffff;
}

__attribute__((always_inline)) uint32_t get_random_smaller_than(uint32_t *state, uint32_t max) {
    uint32_t r;
    int i;
    for (i = 0 ; i < 5 ; i++) {
        r = get_random_u32(state);
        if (r >= (0x7fffffff - 0x7fffffff % max))
            break;
    }

    r %= max;
    return r;
}


__attribute__((always_inline)) int detect_endian(void) {
    static const int i = 2;
    const unsigned char *p = (const unsigned char *) &i;
    return 1 - *p;
}

// returns true if all the results are DROP, false otherwise
__attribute__((always_inline)) int all_drop_f(int results[], int size) {
    int i;
    for (i = 0 ; i < size ; i++) {
        if (results[i] != DROP)
            return false;
    }
    return true;
}

// returns DROP with a probabylity of proba
// retuens PASS otherwise
__attribute__((always_inline)) int drop_if_random_with_proba(uint64_t proba_times_100)
{
    int key = 0, key2 = 1;
    __u32 *state = bpf_map_lookup_elem(&map, &key);
    if(!state || *state == 0) {
        __u32 state = SEED;
        bpf_map_update_elem(&map, &key, &state, BPF_ANY);
        bpf_debug("init seed to %u\n", state);
    }

    state = bpf_map_lookup_elem(&map, &key);
    if (state) {
        uint32_t threshold = (uint32_t) (proba_times_100);
        uint32_t random = get_random_smaller_than(state, (100*100));
        bpf_map_update_elem(&map, &key, state, BPF_ANY);
        if (random < threshold) {
            if (!GEMODEL)
                bpf_debug("DROP PACKET WITH LOSS RATE OF %u (%u < %u)\n", proba_times_100, random, threshold);
            return DROP;
        }
        return PASS;
    }
    return PASS;
}

__attribute__((always_inline)) int gemodel_drop_in_state(gemodel_state state, uint32_t k_times_100, uint32_t h_times_100) {
    if (state == GOOD) {
        __u32 proba_drop_in_good_state_times_100 = 10000 - k_times_100;
        return drop_if_random_with_proba(proba_drop_in_good_state_times_100);
    }
    __u32 proba_drop_in_bad_state_times_100 = 10000 - h_times_100;
    return drop_if_random_with_proba(proba_drop_in_bad_state_times_100);
}

__attribute__((always_inline)) gemodel_state next_state(gemodel_state state, uint32_t p_times_100, uint32_t r_times_100) {
    if (state == GOOD) {
        return drop_if_random_with_proba(p_times_100) == DROP ? BAD : GOOD;
    }
    return drop_if_random_with_proba(r_times_100) == DROP ? GOOD : BAD;
}

// returns DROP with a probabylity of proba
// retuens PASS otherwise
__attribute__((always_inline)) int drop_if_gemodel(__u32 p_times_100, __u32 r_times_100, __u32 k_times_100, __u32 h_times_100)
{
    int key = 1;
    __u32 *state = bpf_map_lookup_elem(&map, &key);
    if(!state || *state == 0) {
        __u32 state = GOOD;
        bpf_map_update_elem(&map, &key, &state, BPF_ANY);
        bpf_debug("init state to GOOD\n");
    }

    state = bpf_map_lookup_elem(&map, &key);
    if (state) {
        int maybe_drop = gemodel_drop_in_state(*state, GEMODEL_K_PERCENTS_TIMES_100, GEMODEL_H_PERCENTS_TIMES_100);
        __u32 old_state = *state;
        *state = (__u32) next_state(*state, GEMODEL_P_PERCENTS_TIMES_100, GEMODEL_R_PERCENTS_TIMES_100);
        if (old_state != *state) {
            if (*state == GOOD)
                bpf_debug("GO TO GOOD STATE, SEED = %u\n", SEED);
            else
                bpf_debug("GO TO BAD STATE, SEED = %u\n", SEED);
        }
        bpf_map_update_elem(&map, &key, state, BPF_ANY);
        if (maybe_drop == DROP) {
            bpf_debug("DROP PACKET WITH GEMODEL p = %u, r = %u, k = %u, \n", GEMODEL_P_PERCENTS_TIMES_100, GEMODEL_R_PERCENTS_TIMES_100, GEMODEL_K_PERCENTS_TIMES_100);
            bpf_debug("h = %u, SEED = %d\n", GEMODEL_H_PERCENTS_TIMES_100, SEED);
            return DROP;
        }
        return PASS;
    }
    return PASS;
}

__attribute__((always_inline)) __u32 be32_to_he(__u32 a) {
    if (detect_endian() == 1) return a;
    // in this case, we are in little endian
    __u32 retval = 0;
    retval |= (a & 0xFF000000) >> 24;
    retval |= (a & 0x00FF0000) >> 8;
    retval |= (a & 0x0000FF00) << 8;
    retval |= (a & 0x000000FF) << 24;
    return retval;
}

// returns DROP if a == DROP or if b == DROP
// returns PASS otherwise
__attribute__((always_inline)) int OR(int a, int b) {
    return a == DROP || b == DROP ? DROP : PASS;
}

// returns DROP if a == DROP and if b == DROP
// returns PASS otherwise
__attribute__((always_inline)) int AND(int a, int b) {
    return a == DROP && b == DROP ? DROP : PASS;
}

// returns the IP dest address as a 32 bits unsigned integer
__attribute__((always_inline)) __u32 get_daddr(struct __sk_buff *skb) {
    struct iphdr *iphdr = (struct iphdr *) skb + ETH_HLEN;
    ////// LOAD IP ADDR BYTE PER BYTE
    __u32 b1 = ((__u32) load_byte(skb, ETH_HLEN + offsetof(struct iphdr, daddr)) << 24);
    __u32 b2 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, daddr) + 1) << 16;
    __u32 b3 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, daddr) + 2) << 8;
    __u32 b4 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, daddr) + 3);
    ////// END LOAD IP ADDR BYTE PER BYTE
    return (b1 + b2 + b3 + b4);
}

// returns the IP dest address as a 32 bits unsigned integer
__attribute__((always_inline)) __u32 get_saddr(struct __sk_buff *skb) {
    struct iphdr *iphdr = (struct iphdr *) skb + ETH_HLEN;
    ////// LOAD IP ADDR BYTE PER BYTE
    __u32 b1 = ((__u32) load_byte(skb, ETH_HLEN + offsetof(struct iphdr, saddr)) << 24);
    __u32 b2 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, saddr) + 1) << 16;
    __u32 b3 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, saddr) + 2) << 8;
    __u32 b4 = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, saddr) + 3);
    ////// END LOAD IP ADDR BYTE PER BYTE
    return (b1 + b2 + b3 + b4);
}

// returns the dest port as a 16 bits unsigned integer
__attribute__((always_inline)) __u16 get_udp_dport(struct __sk_buff *skb) {
    ////// LOAD DEST PORT BYTE PER BYTE
    __u16 b1 = ((__u32) load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest)) << 8);
    __u16 b2 = ((__u32) load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest) + 1));
    ////// END LOAD DEST PORT BYTE PER BYTE
    return (b1 + b2);
}

// returns the dest port as a 16 bits unsigned integer
__attribute__((always_inline)) __u16 get_udp_sport(struct __sk_buff *skb) {
    ////// LOAD SOURCE PORT BYTE PER BYTE
    __u16 b1 = ((__u32) load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source)) << 8);
    __u16 b2 = ((__u32) load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source) + 1));
    ////// END LOAD SOURCE PORT BYTE PER BYTE
    return (b1 + b2);
}

__attribute__((always_inline)) int drop_if_src_dst_addr(struct __sk_buff *skb, __u32 src, __u32 dst) {
    return (src == get_saddr(skb) && dst == get_daddr(skb)) ? DROP : PASS;
}

__attribute__((always_inline)) int drop_if_addrs(struct __sk_buff *skb, __u32 ip1, __u32 ip2) {
    __u32 saddr = get_saddr(skb);
    __u32 daddr = get_daddr(skb);
    if (ip1 != saddr && ip1 != daddr)
        return PASS;
    if (ip2 != saddr && ip2 != daddr)
        return PASS;
    return ((ip1 == saddr && ip2 == daddr) || (ip1 == daddr && ip2 == saddr)) ? DROP : PASS;
}

__attribute__((always_inline)) int drop_if_udp_port(struct __sk_buff *skb, __u16 port) {
    __u16 sport = get_udp_sport(skb);
    __u16 dport = get_udp_dport(skb);

    int key = 0;
    __u32 *state = bpf_map_lookup_elem(&map, &key);
    if(sport == 6121 && state && *state != 0)
        bpf_debug("sport = %u, state = %u, seed = %u\n", sport, *state, SEED);
    return (port == sport || port == dport) ? DROP : PASS;
}

__attribute__((always_inline)) int drop_if_protocol(struct __sk_buff *skb, __u8 proto) {
    return (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) == proto) ? DROP : PASS;
}

// user defined decision function
// returns DROP when a packet must be dropped
// returns PASS otherwise
__attribute__((always_inline)) int decision_function(struct __sk_buff *skb) {
    // to be completed by the user
    if (ALL_DROP(drop_if_udp_port(skb, PORT_TO_WATCH), drop_if_protocol(skb, UDP), drop_if_addrs(skb, IP1_TO_DROP, IP2_TO_DROP))){
        if (GEMODEL)
            return drop_if_gemodel(GEMODEL_P_PERCENTS_TIMES_100, GEMODEL_R_PERCENTS_TIMES_100, GEMODEL_K_PERCENTS_TIMES_100, GEMODEL_H_PERCENTS_TIMES_100);
        else
            return drop_if_random_with_proba(PROBA_percents_times_100);
    }
    return PASS;
}

// modified by the user to wrap the decision function with other functions
// returns DROP when a packet must be dropped
// returns PASS otherwise
SEC("action") int handle_ingress(struct __sk_buff *skb)
{
    // to be completed by the user
    return decision_function(skb);
}

char _license[] SEC("license") = "GPL";
