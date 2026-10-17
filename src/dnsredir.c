/*
 * Zero-Allocation DNS UDP Connection Tracker for GoodbyeDPI
 *
 * Uses a static, cache-line aligned open-addressed hash table with
 * hardware SSE4.2 CRC32C hashing and zero-syscall GetTickCount64()
 * timestamps. Eliminates malloc/free and linear table scans from the
 * packet-processing hot path.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "goodbyedpi.h"
#include "dnsredir.h"

#define DNS_CLEANUP_INTERVAL_MS 30000ULL
#define DNS_TABLE_BITS          12u
#define DNS_TABLE_SIZE          (1u << DNS_TABLE_BITS)
#define DNS_TABLE_MASK          (DNS_TABLE_SIZE - 1u)
#define DNS_PROBE_WINDOW        8u

typedef struct {
    uint64_t tick_ms;      /* 0 = empty slot; otherwise monotonic ms (| 1ULL) */
    uint32_t srcip[4];
    uint32_t dstip[4];
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  is_ipv6;
} dns_connrecord_t;

static dns_connrecord_t conntrack_table[DNS_TABLE_SIZE] __attribute__((aligned(64)));

/**
 * Flush DNS resolver cache in Windows
 * Ensures redirected DNS changes take effect immediately
 */
void flush_dns_cache() {
    INT_PTR WINAPI (*DnsFlushResolverCache)();

    HMODULE dnsapi = LoadLibrary("dnsapi.dll");
    if (dnsapi == NULL)
    {
        printf("Can't load dnsapi.dll to flush DNS cache!\n");
        exit(EXIT_FAILURE);
    }

    DnsFlushResolverCache = GetProcAddress(dnsapi, "DnsFlushResolverCache");
    if (DnsFlushResolverCache == NULL || !DnsFlushResolverCache())
        printf("Can't flush DNS cache!");
    FreeLibrary(dnsapi);
}

static inline uint32_t hash_dns_key(const uint32_t *srcip, uint16_t srcport, uint8_t is_ipv6) {
    uint64_t k0 = ((uint64_t)is_ipv6 << 48) | ((uint64_t)srcport << 32) | (uint64_t)srcip[0];
    uint32_t h = fast_hash_u64(0x9E3779B97F4A7C15ULL, k0);
    if (UNLIKELY(is_ipv6)) {
        uint64_t k1 = ((uint64_t)srcip[1] << 32) | (uint64_t)srcip[2];
        h = fast_hash_u64(h, k1 ^ (uint64_t)srcip[3]);
    }
    return h;
}

static inline int match_dns_key(const dns_connrecord_t *rec, const uint32_t *srcip,
                                uint16_t srcport, uint8_t is_ipv6) {
    if (rec->srcport != srcport || rec->is_ipv6 != is_ipv6)
        return 0;
    if (!is_ipv6)
        return rec->srcip[0] == srcip[0];
    return memcmp(rec->srcip, srcip, sizeof(uint32_t) * 4) == 0;
}

/**
 * Check if a packet looks like a DNS request/response
 */
int dns_is_dns_packet(const char *packet_data, const UINT packet_dataLen, const int outgoing) {
    if (packet_dataLen < 16) return FALSE;

    const uint8_t *p = (const uint8_t *)packet_data;
    uint16_t flags = ((uint16_t)p[2] << 8) | p[3];
    uint16_t ancount = ((uint16_t)p[6] << 8) | p[7];
    uint16_t nscount = ((uint16_t)p[8] << 8) | p[9];

    if (outgoing && (flags & 0xFA00u) == 0 && ancount == 0 && nscount == 0) {
        return TRUE;
    }
    else if (!outgoing && (flags & 0xF800u) == 0x8000u) {
        return TRUE;
    }
    return FALSE;
}

/**
 * Handle outgoing DNS requests
 * Tracks them for later correlation with responses without heap allocation
 */
int dns_handle_outgoing(const uint32_t *srcip, const uint16_t srcport,
                        const uint32_t *dstip, const uint16_t dstport,
                        const char *packet_data, const UINT packet_dataLen,
                        const uint8_t is_ipv6)
{
    if (UNLIKELY(!(srcip && srcport && dstip && dstport) || packet_dataLen < 16))
        return FALSE;

    if (!dns_is_dns_packet(packet_data, packet_dataLen, 1))
        return FALSE;

    uint64_t now = (uint64_t)GetTickCount64() | 1ULL;
    uint32_t base = hash_dns_key(srcip, srcport, is_ipv6);
    dns_connrecord_t *target = NULL;

    for (uint32_t i = 0; i < DNS_PROBE_WINDOW; i++) {
        dns_connrecord_t *slot = &conntrack_table[(base + i) & DNS_TABLE_MASK];
        if (slot->tick_ms == 0 || (now - slot->tick_ms) >= DNS_CLEANUP_INTERVAL_MS) {
            if (!target) target = slot;
            if (slot->tick_ms == 0) break;
        } else if (match_dns_key(slot, srcip, srcport, is_ipv6)) {
            return FALSE;
        }
    }

    if (!target) {
        target = &conntrack_table[base & DNS_TABLE_MASK];
    }

    target->tick_ms = now;
    target->srcport = srcport;
    target->dstport = dstport;
    target->is_ipv6 = is_ipv6;
    if (is_ipv6) {
        ipv6_copy_addr(target->srcip, srcip);
        ipv6_copy_addr(target->dstip, dstip);
    } else {
        ipv4_copy_addr(target->srcip, srcip);
        ipv4_copy_addr(target->dstip, dstip);
    }
    return TRUE;
}

/**
 * Handle incoming DNS responses
 * Correlates them with tracked requests and provides redirection info
 */
int dns_handle_incoming(const uint32_t *srcip, const uint16_t srcport,
                        const char *packet_data, const UINT packet_dataLen,
                        conntrack_info_t *conn_info, const uint8_t is_ipv6)
{
    if (UNLIKELY(packet_dataLen < 16 || !conn_info || !srcip))
        return FALSE;

    if (!dns_is_dns_packet(packet_data, packet_dataLen, 0))
        return FALSE;

    uint64_t now = (uint64_t)GetTickCount64() | 1ULL;
    uint32_t base = hash_dns_key(srcip, srcport, is_ipv6);

    for (uint32_t i = 0; i < DNS_PROBE_WINDOW; i++) {
        dns_connrecord_t *slot = &conntrack_table[(base + i) & DNS_TABLE_MASK];
        if (slot->tick_ms == 0)
            continue;
        if ((now - slot->tick_ms) >= DNS_CLEANUP_INTERVAL_MS) {
            slot->tick_ms = 0;
            continue;
        }
        if (match_dns_key(slot, srcip, srcport, is_ipv6)) {
            conn_info->is_ipv6 = slot->is_ipv6;
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
