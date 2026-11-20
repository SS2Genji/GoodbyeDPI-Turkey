/**
 * TurkDPI — Unified Zero-Allocation Connection Tracker & Host Matcher
 *
 * Replaces legacy dnsredir.c, ttltrack.c, blackwhitelist.c, and uthash.h with:
 *   1. Native in-process DnsFlushResolverCache() via dnsapi.dll (zero cmd.exe spawn)
 *   2. 64-byte cache-line-aligned open-addressed DNS UDP/TCP redirection tracker
 *   3. 64-byte cache-line-aligned open-addressed TCP SYN-ACK Auto-TTL hop tracker
 *   4. Zero-copy case-insensitive domain suffix hash table
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <windows.h>
#include "turkdpi.h"

/* ============================================================================
 * 1. Native Windows DNS Resolver Cache Flush (In-Process via dnsapi.dll)
 * ============================================================================ */
typedef BOOL (WINAPI *dns_flush_proc_t)(void);

void flush_dns_cache(void) {
#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
    static HMODULE h_dnsapi = NULL;
    static dns_flush_proc_t fn_flush = NULL;
    static int initialized = 0;

    if (!initialized) {
        initialized = 1;
        h_dnsapi = LoadLibraryA("dnsapi.dll");
        if (h_dnsapi) {
            fn_flush = (dns_flush_proc_t)(uintptr_t)GetProcAddress(h_dnsapi, "DnsFlushResolverCache");
        }
    }
    if (fn_flush) {
        fn_flush();
        return;
    }
    system("ipconfig /flushdns > nul 2>&1");
#endif
}

/* ============================================================================
 * 2. Zero-Allocation DNS Conntrack (UDP/TCP 53 <-> Redirected DNS Server)
 * ============================================================================ */
#define UDP_CLEANUP_TIMEOUT_MS 30000ULL
#define DNS_TABLE_BITS         11
#define DNS_TABLE_SIZE         (1u << DNS_TABLE_BITS)
#define DNS_TABLE_MASK         (DNS_TABLE_SIZE - 1u)
#define DNS_MAX_PROBE          16u

typedef struct ALIGN64 {
    uint64_t time_ms;
    uint32_t srcip[4];
    uint32_t dstip[4];
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  is_ipv6;
    uint8_t  occupied;
    uint8_t  _pad[18];
} dns_slot_t;

static ALIGN64 dns_slot_t g_dns_table[DNS_TABLE_SIZE];

static inline uint32_t hash_dns_tuple(const uint32_t *srcip, uint16_t srcport, uint8_t is_ipv6) {
    uint64_t w0, w1;
    if (!is_ipv6) {
        w0 = ((uint64_t)srcip[0] << 32) | (uint64_t)srcport;
        w1 = (uint64_t)is_ipv6;
    } else {
        uint64_t ip_lo = ((uint64_t)srcip[1] << 32) | srcip[0];
        uint64_t ip_hi = ((uint64_t)srcip[3] << 32) | srcip[2];
        w0 = ip_lo ^ ((uint64_t)srcport << 16);
        w1 = ip_hi ^ (uint64_t)is_ipv6;
    }
    return fast_hash_u64(w0, w1);
}

static inline int dns_key_equals(const dns_slot_t *slot, const uint32_t *srcip,
                                 uint16_t srcport, uint8_t is_ipv6) {
    if (slot->srcport != srcport || slot->is_ipv6 != is_ipv6) return 0;
    if (!is_ipv6) return slot->srcip[0] == srcip[0];
    return memcmp(slot->srcip, srcip, 16) == 0;
}

int dns_is_dns_packet(const char *packet_data, const unsigned int packet_dataLen, const int outgoing) {
    if (packet_dataLen < 16) return 0;
    uint16_t flags_net;
    uint32_t counts_net;
    memcpy(&flags_net, packet_data + 2, 2);
    memcpy(&counts_net, packet_data + 6, 4);
    if (outgoing && (ntohs(flags_net) & 0xFA00) == 0 && counts_net == 0) {
        return 1;
    }
    if (!outgoing && (ntohs(flags_net) & 0x8000) != 0) {
        return 1;
    }
    return 0;
}

size_t dns_extract_qname(const char *packet_data, unsigned int packet_dataLen,
                         char *out_host, size_t out_cap) {
    if (!packet_data || !out_host || out_cap < 2 || packet_dataLen < 17)
        return 0;

    const unsigned char *p = (const unsigned char *)packet_data;
    if ((p[2] & 0x80u) != 0)
        return 0;
    unsigned int qdcount = ((unsigned int)p[4] << 8) | (unsigned int)p[5];
    if (qdcount == 0)
        return 0;

    unsigned int pos = 12;
    size_t out_len = 0;
    int terminated = 0;

    while (pos < packet_dataLen) {
        unsigned char label_len = p[pos++];
        if (label_len == 0) {
            terminated = 1;
            break;
        }
        /* Reject DNS compression pointers (>= 0xC0) and invalid labels (> 63) */
        if ((label_len & 0xC0u) != 0 || label_len > 63u)
            return 0;
        /* Label bytes + root terminator (0x00) must fit within packet_dataLen */
        if (pos + (unsigned int)label_len >= packet_dataLen)
            return 0;

        if (out_len > 0) {
            if (out_len + 1 >= out_cap)
                return 0;
            out_host[out_len++] = '.';
        }
        if (out_len + (size_t)label_len >= out_cap)
            return 0;

        for (unsigned char j = 0; j < label_len; j++) {
            uint8_t ch = p[pos + j];
            if (ch == 0 || ch == '.')
                return 0;
            if (ch >= 'A' && ch <= 'Z')
                ch |= 0x20u;
            out_host[out_len++] = (char)ch;
        }
        pos += (unsigned int)label_len;
    }

    if (!terminated || out_len == 0 || pos + 4u > packet_dataLen)
        return 0;

    out_host[out_len] = '\0';
    return out_len;
}

int dns_handle_outgoing(const uint32_t *srcip, const uint16_t srcport,
                        const uint32_t *dstip, const uint16_t dstport,
                        const char *packet_data, const unsigned int packet_dataLen,
                        const int is_ipv6) {
    if (!dns_is_dns_packet(packet_data, packet_dataLen, 1))
        return 0;

    const uint64_t now_ms = GetTickCount64();
    const uint8_t v6 = (uint8_t)(is_ipv6 != 0);
    const uint32_t h = hash_dns_tuple(srcip, srcport, v6);
    uint32_t target_idx = DNS_TABLE_SIZE;

    for (uint32_t probe = 0; probe < DNS_MAX_PROBE; probe++) {
        uint32_t idx = (h + probe) & DNS_TABLE_MASK;
        dns_slot_t *slot = &g_dns_table[idx];

        if (slot->occupied) {
            if (dns_key_equals(slot, srcip, srcport, v6)) {
                slot->time_ms = now_ms;
                slot->dstport = dstport;
                if (!v6) slot->dstip[0] = dstip[0];
                else memcpy(slot->dstip, dstip, 16);
                return 1;
            }
            if (target_idx == DNS_TABLE_SIZE && (now_ms - slot->time_ms >= UDP_CLEANUP_TIMEOUT_MS)) {
                target_idx = idx;
            }
        } else if (target_idx == DNS_TABLE_SIZE) {
            target_idx = idx;
        }
    }

    if (target_idx == DNS_TABLE_SIZE) {
        target_idx = h & DNS_TABLE_MASK;
    }

    dns_slot_t *dst = &g_dns_table[target_idx];
    dst->time_ms = now_ms;
    dst->srcport = srcport;
    dst->dstport = dstport;
    dst->is_ipv6 = v6;
    dst->occupied = 1;
    if (!v6) {
        dst->srcip[0] = srcip[0];
        dst->dstip[0] = dstip[0];
    } else {
        memcpy(dst->srcip, srcip, 16);
        memcpy(dst->dstip, dstip, 16);
    }
    return 1;
}

int dns_handle_incoming(const uint32_t *srcip, const uint16_t srcport,
                        const uint32_t *dstip, const uint16_t dstport,
                        const char *packet_data, const unsigned int packet_dataLen,
                        conntrack_info_t *conn_info, const int is_ipv6) {
    (void)srcip;
    (void)srcport;

    if (!dns_is_dns_packet(packet_data, packet_dataLen, 0) || !conn_info)
        return 0;

    const uint64_t now_ms = GetTickCount64();
    const uint8_t v6 = (uint8_t)(is_ipv6 != 0);
    const uint32_t h = hash_dns_tuple(dstip, dstport, v6);

    for (uint32_t probe = 0; probe < DNS_MAX_PROBE; probe++) {
        uint32_t idx = (h + probe) & DNS_TABLE_MASK;
        dns_slot_t *slot = &g_dns_table[idx];

        if (!slot->occupied) continue;
        if (now_ms - slot->time_ms >= UDP_CLEANUP_TIMEOUT_MS) {
            slot->occupied = 0;
            continue;
        }
        if (dns_key_equals(slot, dstip, dstport, v6)) {
            conn_info->dstport = slot->dstport;
            if (!v6) conn_info->dstip[0] = slot->dstip[0];
            else memcpy(conn_info->dstip, slot->dstip, 16);
            slot->occupied = 0;
            return 1;
        }
    }
    return 0;
}

void dns_cleanup(void) {
    const uint64_t now_ms = GetTickCount64();
    for (uint32_t i = 0; i < DNS_TABLE_SIZE; i++) {
        if (g_dns_table[i].occupied && (now_ms - g_dns_table[i].time_ms >= UDP_CLEANUP_TIMEOUT_MS)) {
            g_dns_table[i].occupied = 0;
        }
    }
}

/* ============================================================================
 * 3. Zero-Allocation TCP SYN-ACK Auto-TTL Conntrack
 * ============================================================================ */
#define TCP_CLEANUP_TIMEOUT_MS 30000ULL
#define TCP_TABLE_BITS         12
#define TCP_TABLE_SIZE         (1u << TCP_TABLE_BITS)
#define TCP_TABLE_MASK         (TCP_TABLE_SIZE - 1u)
#define TCP_MAX_PROBE          16u

typedef struct ALIGN64 {
    uint64_t time_ms;
    uint32_t srcip[4];
    uint32_t dstip[4];
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  ttl;
    uint8_t  is_ipv6;
    uint8_t  occupied;
    uint8_t  _pad[17];
} tcp_slot_t;

static ALIGN64 tcp_slot_t g_tcp_table[TCP_TABLE_SIZE];

static inline uint32_t hash_tcp_tuple(const uint32_t *client_ip, uint16_t client_port,
                                      const uint32_t *server_ip, uint16_t server_port,
                                      uint8_t is_ipv6) {
    uint64_t ports = ((uint64_t)client_port << 16) | (uint64_t)server_port | ((uint64_t)is_ipv6 << 32);
    if (!is_ipv6) {
        uint64_t ips = ((uint64_t)client_ip[0] << 32) | (uint64_t)server_ip[0];
        return fast_hash_u64(ips, ports);
    } else {
        uint64_t c0 = ((uint64_t)client_ip[1] << 32) | client_ip[0];
        uint64_t c1 = ((uint64_t)client_ip[3] << 32) | client_ip[2];
        uint64_t s0 = ((uint64_t)server_ip[1] << 32) | server_ip[0];
        uint64_t s1 = ((uint64_t)server_ip[3] << 32) | server_ip[2];
        uint32_t h  = fast_hash_u64(c0 ^ s0, c1 ^ s1);
        return fast_hash_u64(h, ports);
    }
}

static inline int tcp_key_equals(const tcp_slot_t *slot,
                                 const uint32_t *client_ip, uint16_t client_port,
                                 const uint32_t *server_ip, uint16_t server_port,
                                 uint8_t is_ipv6) {
    if (slot->srcport != client_port || slot->dstport != server_port || slot->is_ipv6 != is_ipv6)
        return 0;
    if (!is_ipv6)
        return slot->srcip[0] == client_ip[0] && slot->dstip[0] == server_ip[0];
    return memcmp(slot->srcip, client_ip, 16) == 0 && memcmp(slot->dstip, server_ip, 16) == 0;
}

int tcp_handle_incoming(const uint32_t *srcip, uint16_t srcport,
                        const uint32_t *dstip, uint16_t dstport,
                        uint8_t is_ipv6, uint8_t ttl) {
    const uint64_t now_ms = GetTickCount64();
    const uint8_t v6 = (uint8_t)(is_ipv6 != 0);
    const uint32_t h = hash_tcp_tuple(dstip, dstport, srcip, srcport, v6);
    uint32_t target_idx = TCP_TABLE_SIZE;

    for (uint32_t probe = 0; probe < TCP_MAX_PROBE; probe++) {
        uint32_t idx = (h + probe) & TCP_TABLE_MASK;
        tcp_slot_t *slot = &g_tcp_table[idx];

        if (slot->occupied) {
            if (tcp_key_equals(slot, dstip, dstport, srcip, srcport, v6)) {
                slot->time_ms = now_ms;
                slot->ttl = ttl;
                return 1;
            }
            if (target_idx == TCP_TABLE_SIZE && (now_ms - slot->time_ms >= TCP_CLEANUP_TIMEOUT_MS)) {
                target_idx = idx;
            }
        } else if (target_idx == TCP_TABLE_SIZE) {
            target_idx = idx;
        }
    }

    if (target_idx == TCP_TABLE_SIZE) {
        target_idx = h & TCP_TABLE_MASK;
    }

    tcp_slot_t *dst = &g_tcp_table[target_idx];
    dst->time_ms = now_ms;
    dst->srcport = dstport;
    dst->dstport = srcport;
    dst->ttl = ttl;
    dst->is_ipv6 = v6;
    dst->occupied = 1;
    if (!v6) {
        dst->srcip[0] = dstip[0];
        dst->dstip[0] = srcip[0];
    } else {
        memcpy(dst->srcip, dstip, 16);
        memcpy(dst->dstip, srcip, 16);
    }
    return 1;
}

int tcp_handle_outgoing(const uint32_t *srcip, uint16_t srcport,
                        const uint32_t *dstip, uint16_t dstport,
                        tcp_conntrack_info_t *conn_info,
                        uint8_t is_ipv6) {
    if (!conn_info) return 0;

    const uint64_t now_ms = GetTickCount64();
    const uint8_t v6 = (uint8_t)(is_ipv6 != 0);
    const uint32_t h = hash_tcp_tuple(srcip, srcport, dstip, dstport, v6);

    for (uint32_t probe = 0; probe < TCP_MAX_PROBE; probe++) {
        uint32_t idx = (h + probe) & TCP_TABLE_MASK;
        tcp_slot_t *slot = &g_tcp_table[idx];

        if (!slot->occupied) continue;
        if (now_ms - slot->time_ms >= TCP_CLEANUP_TIMEOUT_MS) {
            slot->occupied = 0;
            continue;
        }
        if (tcp_key_equals(slot, srcip, srcport, dstip, dstport, v6)) {
            conn_info->is_ipv6 = slot->is_ipv6;
            conn_info->ttl     = slot->ttl;
            slot->occupied     = 0;
            return 1;
        }
    }
    return 0;
}

uint8_t tcp_get_auto_ttl(const uint8_t ttl, const uint8_t autottl1,
                         const uint8_t autottl2, const uint8_t minhops,
                         const uint8_t maxttl) {
    uint8_t nhops = 0;
    uint8_t ttl_of_fake_packet = 0;

    if (ttl > 98 && ttl < 128) {
        nhops = (uint8_t)(128 - ttl);
    } else if (ttl > 34 && ttl < 64) {
        nhops = (uint8_t)(64 - ttl);
    } else {
        return 0;
    }

    if (nhops <= autottl1 || nhops < minhops) {
        return 0;
    }

    ttl_of_fake_packet = (uint8_t)(nhops - autottl2);
    if (ttl_of_fake_packet < autottl2 && nhops <= 9) {
        ttl_of_fake_packet = (uint8_t)(nhops - autottl1 - (uint8_t)trunc((autottl2 - autottl1) * ((double)nhops / 10.0)));
    }
    if (maxttl && ttl_of_fake_packet > maxttl) {
        ttl_of_fake_packet = maxttl;
    }
    return ttl_of_fake_packet;
}

/* ============================================================================
 * 4. Zero-Copy Case-Insensitive Hostname Matcher (Blacklist / Hostlist)
 * ============================================================================ */
#define HOST_TABLE_BITS 16
#define HOST_TABLE_SIZE (1u << HOST_TABLE_BITS)
#define HOST_TABLE_MASK (HOST_TABLE_SIZE - 1u)

typedef struct {
    uint32_t offset;
    uint32_t hash;
    uint16_t len;
    uint16_t _pad;
} host_slot_t;

static ALIGN64 host_slot_t g_host_table[HOST_TABLE_SIZE];
static char   *g_host_arena = NULL;
static size_t  g_host_arena_size = 0;
static size_t  g_host_arena_cap = 0;

static inline uint32_t hash_host_span_ci(const char *s, size_t len) {
    uint64_t h = 0x9E3779B97F4A7C15ULL ^ len;
    size_t i = 0;
    while (i + 8 <= len) {
        uint64_t w;
        memcpy(&w, s + i, 8);
        w |= 0x2020202020202020ULL;
        h = fast_hash_u64(h, w);
        i += 8;
    }
    uint64_t tail = 0;
    for (size_t j = 0; i + j < len; j++) {
        uint8_t c = (uint8_t)s[i + j] | 0x20u;
        tail |= ((uint64_t)c << (j * 8));
    }
    return fast_hash_u64(h, tail);
}

static inline int host_span_equals_ci(const char *stored_lower, const char *query, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)query[i];
        if (c >= 'A' && c <= 'Z') c |= 0x20u;
        if ((uint8_t)stored_lower[i] != c) return 0;
    }
    return 1;
}

static inline int host_table_lookup(const char *span, size_t len) {
    if (len == 0 || len > HOST_MAXLEN || !g_host_arena) return 0;
    uint32_t h = hash_host_span_ci(span, len);
    for (uint32_t probe = 0; probe < 32; probe++) {
        uint32_t idx = (h + probe) & HOST_TABLE_MASK;
        const host_slot_t *slot = &g_host_table[idx];
        if (slot->len == 0) return 0;
        if (slot->hash == h && slot->len == len &&
            host_span_equals_ci(g_host_arena + slot->offset, span, len))
            return 1;
    }
    return 0;
}

static int host_table_insert(const char *host, size_t len) {
    if (len == 0 || len > HOST_MAXLEN) return 0;
    uint32_t h = hash_host_span_ci(host, len);

    for (uint32_t probe = 0; probe < HOST_TABLE_SIZE; probe++) {
        uint32_t idx = (h + probe) & HOST_TABLE_MASK;
        host_slot_t *slot = &g_host_table[idx];
        if (slot->len == 0) {
            if (g_host_arena_size + len + 1 > g_host_arena_cap) {
                size_t new_cap = g_host_arena_cap ? g_host_arena_cap * 2 : (1024 * 1024);
                while (new_cap < g_host_arena_size + len + 1) new_cap *= 2;
                char *new_arena = (char *)realloc(g_host_arena, new_cap);
                if (!new_arena) return 0;
                g_host_arena = new_arena;
                g_host_arena_cap = new_cap;
            }
            uint32_t off = (uint32_t)g_host_arena_size;
            char *dst = g_host_arena + off;
            for (size_t i = 0; i < len; i++) {
                uint8_t c = (uint8_t)host[i];
                if (c >= 'A' && c <= 'Z') c |= 0x20u;
                dst[i] = (char)c;
            }
            dst[len] = '\0';
            g_host_arena_size += len + 1;

            slot->offset = off;
            slot->len    = (uint16_t)len;
            slot->hash   = h;
            return 1;
        }
        if (slot->hash == h && slot->len == len &&
            host_span_equals_ci(g_host_arena + slot->offset, host, len)) {
            return 0;
        }
    }
    return 0;
}

/* Built-in Turkey blocked-services hostlist (Game-Friendly Targeted Mode).
 * Deliberately excludes rbxcdn.com so tr.rbxcdn.com resolves directly via local
 * ISP Akamai CDN rather than Yandex DNS (77.88.8.8:1253). */
static const char *const g_default_blocked_hosts[] = {
    /* Discord */
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discord.media",
    "discordcdn.com",
    "discordstatus.com",
    "dis.gd",
    "discord.co",
    "discord.new",
    "discord.gift",
    "discord.design",
    "discord.dev",
    "discord.tools",
    "discord-activities.com",
    "discordsays.com",
    "discordpartygames.com",
    /* Roblox */
    "roblox.com",
    "rbx.com",
    "robloxlabs.com",
    "rbxtrk.com",
    "rbxinfra.net",
    "rblx.co",
    /* Wattpad */
    "wattpad.com",
    "w.tt"
};

void blackwhitelist_init_defaults(void) {
    memset(g_host_table, 0, sizeof(g_host_table));
    g_host_arena_size = 0;

    const size_t count = sizeof(g_default_blocked_hosts) / sizeof(g_default_blocked_hosts[0]);
    for (size_t i = 0; i < count; i++) {
        host_table_insert(g_default_blocked_hosts[i], strlen(g_default_blocked_hosts[i]));
    }
}

static int blackwhitelist_read_file(const char *filename) {
    if (!filename) return -1;
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    char line[1024];
    int cnt = 0;
    int first_line = 1;
    while (fgets(line, sizeof(line), fp)) {
        size_t start = 0;
        size_t len = strlen(line);

        if (first_line) {
            first_line = 0;
            if (len >= 3 &&
                (unsigned char)line[0] == 0xEFu &&
                (unsigned char)line[1] == 0xBBu &&
                (unsigned char)line[2] == 0xBFu) {
                start = 3;
            }
        }

        for (size_t k = start; k < len; k++) {
            if (line[k] == '#') {
                len = k;
                break;
            }
        }

        while (len > start &&
               (line[len - 1] == '\r' || line[len - 1] == '\n' ||
                line[len - 1] == ' '  || line[len - 1] == '\t' ||
                line[len - 1] == '.')) {
            len--;
        }
        while (start < len &&
               (line[start] == ' ' || line[start] == '\t' || line[start] == '.')) {
            start++;
        }

        if (start >= len) continue;
        size_t clean_len = len - start;
        if (clean_len > HOST_MAXLEN) continue;
        if (host_table_insert(line + start, clean_len)) cnt++;
    }
    fclose(fp);
    return cnt;
}

bool blackwhitelist_load_list(const char *filename) {
    if (!filename) return false;
    FILE *probe_fp = fopen(filename, "r");
    if (!probe_fp) return false;
    fclose(probe_fp);

    memset(g_host_table, 0, sizeof(g_host_table));
    g_host_arena_size = 0;

    int cnt = blackwhitelist_read_file(filename);
    if (cnt < 0) return false;
    printf("Loaded %d hosts from file %s\n", cnt, filename);
    return true;
}

bool blackwhitelist_append_list(const char *filename) {
    int cnt = blackwhitelist_read_file(filename);
    if (cnt < 0) return false;
    printf("Appended %d custom hosts from file %s\n", cnt, filename);
    return true;
}

bool blackwhitelist_check_hostname(const char *host_addr, size_t host_len) {
    if (!host_addr || host_len == 0 || host_len > HOST_MAXLEN) return false;
    if (host_table_lookup(host_addr, host_len)) return true;

    for (size_t i = 0; i < host_len; i++) {
        if (host_addr[i] == '.' && (i + 1 < host_len)) {
            if (host_table_lookup(host_addr + i + 1, host_len - (i + 1)))
                return true;
        }
    }
    return false;
}
