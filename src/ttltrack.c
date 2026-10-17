/**
 * Zero-Allocation TCP (TTL) Connection Tracker for GoodbyeDPI
 *
 * Monitors SYN/ACK packets to extract remote server TTL values using a
 * static, cache-line aligned open-addressed hash table and hardware
 * SSE4.2 CRC32C hashing.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "goodbyedpi.h"
#include "ttltrack.h"

#define TCP_CLEANUP_INTERVAL_MS 30000ULL
#define TCP_TABLE_BITS          13u
#define TCP_TABLE_SIZE          (1u << TCP_TABLE_BITS)
#define TCP_TABLE_MASK          (TCP_TABLE_SIZE - 1u)
#define TCP_PROBE_WINDOW        8u

typedef struct {
    uint64_t tick_ms;      /* 0 = empty slot; otherwise monotonic ms (| 1ULL) */
    uint32_t srcip[4];
    uint32_t dstip[4];
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  is_ipv6;
    uint8_t  ttl;
} tcp_connrecord_t;

static tcp_connrecord_t conntrack_table[TCP_TABLE_SIZE] __attribute__((aligned(64)));

static inline uint32_t hash_tcp_key(const uint32_t *srcip, const uint32_t *dstip,
                                    uint16_t srcport, uint16_t dstport, uint8_t is_ipv6) {
    uint64_t ports = ((uint64_t)is_ipv6 << 32) | ((uint64_t)srcport << 16) | (uint64_t)dstport;
    uint64_t ips   = ((uint64_t)srcip[0] << 32) | (uint64_t)dstip[0];
    uint32_t h = fast_hash_u64(ports, ips);
    if (UNLIKELY(is_ipv6)) {
        uint64_t s12 = ((uint64_t)srcip[1] << 32) | (uint64_t)srcip[2];
        uint64_t d12 = ((uint64_t)dstip[1] << 32) | (uint64_t)dstip[2];
        h = fast_hash_u64(h, s12 ^ d12);
        h = fast_hash_u64(h, ((uint64_t)srcip[3] << 32) | (uint64_t)dstip[3]);
    }
    return h;
}

static inline int match_tcp_key(const tcp_connrecord_t *rec, const uint32_t *srcip,
                                const uint32_t *dstip, uint16_t srcport,
                                uint16_t dstport, uint8_t is_ipv6) {
    if (rec->srcport != srcport || rec->dstport != dstport || rec->is_ipv6 != is_ipv6)
        return 0;
    if (!is_ipv6)
        return rec->srcip[0] == srcip[0] && rec->dstip[0] == dstip[0];
    return memcmp(rec->srcip, srcip, sizeof(uint32_t) * 4) == 0 &&
           memcmp(rec->dstip, dstip, sizeof(uint32_t) * 4) == 0;
}

int tcp_handle_incoming(const uint32_t *srcip, const uint32_t *dstip,
                        uint16_t srcport, uint16_t dstport,
                        uint8_t is_ipv6, uint8_t ttl)
{
    if (UNLIKELY(!(srcip && srcport && dstip && dstport)))
        return FALSE;

    uint64_t now = (uint64_t)GetTickCount64() | 1ULL;
    uint32_t base = hash_tcp_key(srcip, dstip, srcport, dstport, is_ipv6);
    tcp_connrecord_t *target = NULL;

    for (uint32_t i = 0; i < TCP_PROBE_WINDOW; i++) {
        tcp_connrecord_t *slot = &conntrack_table[(base + i) & TCP_TABLE_MASK];
        if (slot->tick_ms == 0 || (now - slot->tick_ms) >= TCP_CLEANUP_INTERVAL_MS) {
            if (!target) target = slot;
            if (slot->tick_ms == 0) break;
        } else if (match_tcp_key(slot, srcip, dstip, srcport, dstport, is_ipv6)) {
            return FALSE;
        }
    }

    if (!target) {
        target = &conntrack_table[base & TCP_TABLE_MASK];
    }

    target->tick_ms = now;
    target->srcport = srcport;
    target->dstport = dstport;
    target->is_ipv6 = is_ipv6;
    target->ttl     = ttl;
    if (is_ipv6) {
        ipv6_copy_addr(target->srcip, srcip);
        ipv6_copy_addr(target->dstip, dstip);
    } else {
        ipv4_copy_addr(target->srcip, srcip);
        ipv4_copy_addr(target->dstip, dstip);
    }
    return TRUE;
}

int tcp_handle_outgoing(const uint32_t *srcip, const uint32_t *dstip,
                        uint16_t srcport, uint16_t dstport,
                        tcp_conntrack_info_t *conn_info,
                        uint8_t is_ipv6)
{
    if (UNLIKELY(!conn_info || !srcip || !dstip))
        return FALSE;

    uint64_t now = (uint64_t)GetTickCount64() | 1ULL;
    /* Outgoing packet has reversed (dst, src) relative to incoming SYN+ACK */
    uint32_t base = hash_tcp_key(dstip, srcip, dstport, srcport, is_ipv6);

    for (uint32_t i = 0; i < TCP_PROBE_WINDOW; i++) {
        tcp_connrecord_t *slot = &conntrack_table[(base + i) & TCP_TABLE_MASK];
        if (slot->tick_ms == 0)
            continue;
        if ((now - slot->tick_ms) >= TCP_CLEANUP_INTERVAL_MS) {
            slot->tick_ms = 0;
            continue;
        }
        if (match_tcp_key(slot, dstip, srcip, dstport, srcport, is_ipv6)) {
            conn_info->is_ipv6 = slot->is_ipv6;
            conn_info->ttl     = slot->ttl;
            conn_info->srcport = slot->srcport;
            conn_info->dstport = slot->dstport;
            if (is_ipv6) {
                ipv6_copy_addr(conn_info->srcip, slot->srcip);
                ipv6_copy_addr(conn_info->dstip, slot->dstip);
            } else {
                ipv4_copy_addr(conn_info->srcip, slot->srcip);
                ipv4_copy_addr(conn_info->dstip, slot->dstip);
            }
            slot->tick_ms = 0; /* One-shot eviction */
            return TRUE;
        }
    }
    return FALSE;
}

int tcp_get_auto_ttl(const uint8_t ttl, const uint8_t autottl1,
                     const uint8_t autottl2, const uint8_t minhops,
                     const uint8_t maxttl) {
    uint8_t nhops = 0;
    uint8_t ttl_of_fake_packet = 0;

    if (ttl > 98 && ttl < 128) {
        nhops = 128 - ttl;
    }
    else if (ttl > 34 && ttl < 64) {
        nhops = 64 - ttl;
    }
    else {
        return 0;
    }

    if (nhops <= autottl1 || nhops < minhops) {
        return 0;
    }

    ttl_of_fake_packet = nhops - autottl2;
    if (ttl_of_fake_packet < autottl2 && nhops <= 9) {
        ttl_of_fake_packet = (uint8_t)(nhops - autottl1 - (((unsigned int)(autottl2 - autottl1) * nhops) / 10u));
    }

    if (maxttl && ttl_of_fake_packet > maxttl) {
        ttl_of_fake_packet = maxttl;
    }

    return ttl_of_fake_packet;
}