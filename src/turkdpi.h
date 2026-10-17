#ifndef TURKDPI_H
#define TURKDPI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#define TURKDPI_VERSION "2.0.0-TurkDPI"
#define HOST_MAXLEN     253
#define MAX_PACKET_SIZE 9016

#define PACKET_BATCH_MAX      64
#define PACKET_BATCH_BUF_SIZE (PACKET_BATCH_MAX * 1536)

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALIGN64     __attribute__((aligned(64)))
#else
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#define ALIGN64
#endif

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#include <emmintrin.h>
#define TURKDPI_HAVE_SSE2 1
#endif

#if defined(__SSE4_2__)
#include <nmmintrin.h>
#define TURKDPI_HAVE_SSE42 1
#endif

/* Fooling bitmask flags (Zapret / ByeDPI / GoodbyeDPI) */
#define FOOL_NONE    0x00u
#define FOOL_BADSUM  0x01u  /* Corrupt TCP checksum (Turk Telekom / TurkNet / Kablonet) */
#define FOOL_BADSEQ  0x02u  /* Offset TCP SeqNum by -10000 and AckNum by -66000 */
#define FOOL_MD5SIG  0x04u  /* Attach RFC 2385 TCP Option 19 (18B MD5 signature) */
#define FOOL_TTL     0x08u  /* Fixed low TTL on fake packet */
#define FOOL_AUTOTTL 0x10u  /* Dynamic SYN-ACK hop-count TTL */

typedef struct {
    const char *name;
    const char *isp_hint;
    uint8_t     do_passivedpi;
    uint8_t     do_block_quic;
    uint8_t     do_fragment_http;
    uint8_t     do_fragment_http_persistent;
    uint8_t     do_fragment_http_persistent_nowait;
    uint8_t     do_fragment_https;
    uint8_t     do_native_frag;
    uint8_t     do_reverse_frag;
    uint8_t     do_split_sni;       /* ByeDPI / Zapret: split right in the middle of TLS SNI */
    uint8_t     do_host;
    uint8_t     do_host_removespace;
    uint8_t     do_additional_space;
    uint8_t     do_host_mixedcase;
    uint8_t     do_http_allports;
    uint8_t     do_fake_packet;
    uint8_t     fooling_flags;      /* Combination of FOOL_* bitflags */
    uint8_t     fake_ttl;           /* Fixed TTL when FOOL_TTL is set */
    uint8_t     auto_ttl_delta;     /* Subtract from estimated hop count (default 1) */
    uint8_t     auto_ttl_min;       /* Minimum TTL floor (default 3) */
    uint8_t     auto_ttl_max;       /* Maximum TTL ceiling (default 10) */
    uint8_t     do_udp_fake;        /* Discord Voice / WebRTC STUN/DTLS UDP low-TTL decoy */
    uint8_t     do_dnsv4_redirect;
    uint8_t     do_dnsv6_redirect;
    uint8_t     do_dns_verb;
    uint8_t     do_tcp_verb;
    uint8_t     do_blacklist;
    uint8_t     do_allow_no_sni;
    uint8_t     do_fragment_by_sni;
    uint16_t    http_frag_size;
    uint16_t    https_frag_size;
    uint16_t    max_payload_size;
    uint32_t    dnsv4_addr;         /* Network byte order */
    uint16_t    dnsv4_port;         /* Network byte order */
    uint8_t     dnsv6_addr[16];     /* Network byte order */
    uint16_t    dnsv6_port;         /* Network byte order */
    uint8_t     min_nhops;
} dpi_profile_t;

typedef struct {
    const char *host_ptr;
    uint16_t    host_len;
    uint16_t    host_offset;        /* Byte offset of SNI hostname from start of TCP payload */
} sni_info_t;

/**
 * RFC 1624 incremental 16-bit one's complement checksum update:
 * HC' = ~(~HC + ~m + m')
 */
static inline uint16_t checksum_update_uint16(uint16_t old_check, uint16_t old_val, uint16_t new_val) {
    uint32_t sum = (uint32_t)(uint16_t)~old_check + (uint32_t)(uint16_t)~old_val + (uint32_t)new_val;
    sum = (sum & 0xFFFFu) + (sum >> 16);
    sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline uint16_t checksum_update_uint32(uint16_t old_check, uint32_t old_val, uint32_t new_val) {
    uint16_t c = checksum_update_uint16(old_check, (uint16_t)(old_val & 0xFFFFu), (uint16_t)(new_val & 0xFFFFu));
    return checksum_update_uint16(c, (uint16_t)(old_val >> 16), (uint16_t)(new_val >> 16));
}

static inline uint16_t udp_checksum_fix_zero(uint16_t check) {
    return check == 0 ? 0xFFFFu : check;
}

/**
 * Hardware SSE4.2 CRC32C 64-bit hash with SplitMix64 fallback.
 */
static inline uint32_t fast_hash_u64(uint64_t seed, uint64_t val) {
#if defined(TURKDPI_HAVE_SSE42) && defined(__x86_64__)
    return (uint32_t)_mm_crc32_u64(seed, val);
#elif defined(TURKDPI_HAVE_SSE42)
    uint32_t h = _mm_crc32_u32((uint32_t)seed, (uint32_t)val);
    return _mm_crc32_u32(h, (uint32_t)(val >> 32));
#else
    val ^= seed;
    val = (val ^ (val >> 30)) * 0xbf58476d1ce4e5b9ULL;
    val = (val ^ (val >> 27)) * 0x94d049bb133111ebULL;
    return (uint32_t)(val ^ (val >> 31));
#endif
}

/**
 * SIMD-accelerated substring search (SSE2 16-byte first/last byte vector broadcast).
 */
static inline char *fast_memmem(const char *haystack, size_t hlen,
                                const char *needle, size_t nlen) {
    if (UNLIKELY(nlen == 0)) return (char *)(uintptr_t)haystack;
    if (UNLIKELY(hlen < nlen)) return NULL;

    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;

    if (nlen == 1) {
        return (char *)(uintptr_t)memchr(h, n[0], hlen);
    }

    const size_t last_idx = nlen - 1;
    const size_t limit = hlen - nlen;
    size_t i = 0;

#if defined(TURKDPI_HAVE_SSE2)
    if (limit >= 16) {
        const __m128i v_first = _mm_set1_epi8((char)n[0]);
        const __m128i v_last  = _mm_set1_epi8((char)n[last_idx]);

        for (; i + 16 <= limit + 1; i += 16) {
            __m128i block_first = _mm_loadu_si128((const __m128i *)(h + i));
            __m128i block_last  = _mm_loadu_si128((const __m128i *)(h + i + last_idx));
            __m128i eq_first    = _mm_cmpeq_epi8(v_first, block_first);
            __m128i eq_last     = _mm_cmpeq_epi8(v_last, block_last);
            uint32_t mask       = (uint32_t)_mm_movemask_epi8(_mm_and_si128(eq_first, eq_last));

            while (mask != 0) {
                unsigned int bit = (unsigned int)__builtin_ctz(mask);
                size_t pos = i + bit;
                if (nlen <= 2 || memcmp(h + pos + 1, n + 1, nlen - 2) == 0) {
                    return (char *)(uintptr_t)(h + pos);
                }
                mask &= (mask - 1u);
            }
        }
    }
#endif

    const unsigned char first = n[0];
    const unsigned char last  = n[last_idx];
    for (; i <= limit; i++) {
        if (h[i] == first && h[i + last_idx] == last) {
            if (nlen <= 2 || memcmp(h + i + 1, n + 1, nlen - 2) == 0) {
                return (char *)(uintptr_t)(h + i);
            }
        }
    }
    return NULL;
}

/**
 * Structural O(extensions) TLS 1.2 / TLS 1.3 / Post-Quantum ClientHello SNI parser.
 * Extracts the Server Name Indication (extension 0x0000) hostname and its exact
 * byte offset inside the TCP payload so the desync engine can split right across
 * the middle of the SNI domain name (Zapret midsld / ByeDPI split-by-sni).
 */
static inline int extract_sni_info(const char *pkt, unsigned int pkt_len, sni_info_t *out) {
    const unsigned char *p = (const unsigned char *)pkt;

    /* Minimum TLS Record (5) + Handshake (4) + Version (2) + Random (32) + SessionIDLen (1) = 44B */
    if (pkt_len < 44) return 0;
    if (p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01) return 0;

    unsigned int pos = 43;
    unsigned int sid_len = p[pos];
    pos += 1 + sid_len;
    if (pos + 2 > pkt_len) return 0;

    unsigned int ciph_len = ((unsigned int)p[pos] << 8) | p[pos + 1];
    pos += 2 + ciph_len;
    if (pos + 1 > pkt_len) return 0;

    unsigned int comp_len = p[pos];
    pos += 1 + comp_len;
    if (pos + 2 > pkt_len) return 0;

    unsigned int ext_total_len = ((unsigned int)p[pos] << 8) | p[pos + 1];
    pos += 2;
    unsigned int ext_end = pos + ext_total_len;
    if (ext_end > pkt_len) ext_end = pkt_len;

    while (pos + 4 <= ext_end) {
        unsigned int ext_type = ((unsigned int)p[pos] << 8) | p[pos + 1];
        unsigned int ext_len  = ((unsigned int)p[pos + 2] << 8) | p[pos + 3];
        pos += 4;
        if (pos + ext_len > ext_end) return 0;

        if (ext_type == 0x0000) { /* server_name */
            if (ext_len < 5) return 0;
            unsigned int sni_list_len = ((unsigned int)p[pos] << 8) | p[pos + 1];
            if (sni_list_len + 2 > ext_len || p[pos + 2] != 0x00) return 0;
            unsigned int name_len = ((unsigned int)p[pos + 3] << 8) | p[pos + 4];
            if (name_len == 0 || name_len > HOST_MAXLEN || 5 + name_len > ext_len) return 0;
            unsigned int name_offset = pos + 5;
            if (name_offset + name_len > pkt_len) return 0;

            out->host_ptr    = pkt + name_offset;
            out->host_len    = (uint16_t)name_len;
            out->host_offset = (uint16_t)name_offset;
            return 1;
        }
        pos += ext_len;
    }
    return 0;
}

/* Conntrack structs (DNS redirection + TCP Auto-TTL) */
typedef struct {
    uint32_t dstip[4];
    uint16_t dstport;
} conntrack_info_t;

typedef struct {
    uint8_t is_ipv6;
    uint8_t ttl;
} tcp_conntrack_info_t;

/* Conntrack API (src/conntrack.c) */
void flush_dns_cache(void);
int  dns_is_dns_packet(const char *packet_data, unsigned int packet_dataLen, int outgoing);
int  dns_handle_outgoing(const uint32_t *srcip, const uint16_t srcport,
                         const uint32_t *dstip, const uint16_t dstport,
                         const char *packet_data, const unsigned int packet_dataLen,
                         const int is_ipv6);
int  dns_handle_incoming(const uint32_t *srcip, const uint16_t srcport,
                         const uint32_t *dstip, const uint16_t dstport,
                         const char *packet_data, const unsigned int packet_dataLen,
                         conntrack_info_t *conn_info, const int is_ipv6);
void dns_cleanup(void);

int  tcp_handle_incoming(const uint32_t *srcip, uint16_t srcport,
                         const uint32_t *dstip, uint16_t dstport,
                         uint8_t is_ipv6, uint8_t ttl);
int  tcp_handle_outgoing(const uint32_t *srcip, uint16_t srcport,
                         const uint32_t *dstip, uint16_t dstport,
                         tcp_conntrack_info_t *conn_info,
                         uint8_t is_ipv6);
uint8_t tcp_get_auto_ttl(const uint8_t ttl, const uint8_t autottl1,
                         const uint8_t autottl2, const uint8_t minhops,
                         const uint8_t maxttl);

bool blackwhitelist_load_list(const char *filename);
bool blackwhitelist_check_hostname(const char *host_addr, size_t host_len);

/* Built-in Turkish ISP Profiles & Desync API (src/desync.c) */
#define TURKDPI_NUM_PROFILES 7
extern const dpi_profile_t g_turkdpi_profiles[TURKDPI_NUM_PROFILES];

void desync_init_defaults(void);
int  desync_add_custom_fake(unsigned char *data, size_t len);
int  desync_load_fake_hex(const char *hex_raw);
int  desync_load_fake_sni(const char *domain_name);
void desync_cleanup(void);

int  desync_send_fake_tcp(const void *w_filter,
                          const void *addr,
                          const char *pkt,
                          unsigned int pktLen,
                          int is_ipv6,
                          uint8_t set_ttl,
                          uint8_t fooling_flags,
                          int is_https);
int  desync_send_tcp_split(void *w_filter,
                           const void *addr_ptr,
                           const char *packet,
                           unsigned int packetLen,
                           void *packet_data,
                           unsigned int packet_dataLen,
                           int packet_v4,
                           int packet_v6,
                           void *ppIpHdr,
                           void *ppIpV6Hdr,
                           void *ppTcpHdr,
                           unsigned int split_pos1,
                           unsigned int split_pos2,
                           int reverse_order);
int  desync_is_discord_or_webrtc_udp(uint16_t srcport_net, uint16_t dstport_net,
                                     const unsigned char *pld, unsigned int pld_len);
int  desync_send_udp_fake(void *w_filter,
                          const void *addr,
                          const char *pkt,
                          unsigned int pktLen,
                          int is_ipv6);

/* In-Process ISP Auto-Probe & Diagnostics API (src/probe.c) */
int  probe_build_tls_client_hello(unsigned char *buf, size_t max_len, const char *sni_host);
int  probe_build_dns_query(unsigned char *buf, size_t max_len, const char *domain, uint16_t txid);
uint32_t probe_parse_dns_a_record(const unsigned char *buf, size_t len, uint16_t expected_txid);
int  probe_test_https_target(uint32_t ip_net, uint16_t port_host, const char *sni_host, int timeout_ms);
uint32_t probe_resolve_domain(const char *domain, uint32_t fallback_ip_net);
int  probe_find_best_profile(volatile const dpi_profile_t **active_profile_ptr);

#endif /* TURKDPI_H */
