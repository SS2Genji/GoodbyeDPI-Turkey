/**
 * TurkDPI — Next-Gen Multi-Strategy DPI Desynchronization Engine
 *
 * Combines techniques from Zapret (nfqws/winws), ByeDPI (ciadpi), and GoodbyeDPI:
 *   - SNI-Midpoint 3-Way Multi-Split & Reverse Disorder (single WinDivertSendEx batch)
 *   - Multi-Fooling Decoy Injection:
 *       * FOOL_MD5SIG  (RFC 2385 TCP Option 19 — dropped by Linux/Cloudflare kernels)
 *       * FOOL_BADSEQ  (Out-of-window TCP Sequence/Ack offset: Seq-10000, Ack-66000)
 *       * FOOL_BADSUM  (RFC 1624 O(1) differential corrupted TCP checksum)
 *       * FOOL_AUTOTTL (Dynamic hop-count TTL from SYN-ACK conntrack)
 *   - Discord Voice / WebRTC UDP Desync (STUN / Discord IP Discovery / DTLS decoy)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>
#include "windivert.h"
#include "turkdpi.h"

/* ============================================================================
 * 1. Built-in Turkish ISP Profiles (Ordered for Turkish ISPs)
 * ============================================================================
 * Note on network-byte-order IPv4 constants on little-endian x86:
 *   77.88.8.8  -> 0x0808584Du, port 1253 -> 0xE504u
 *   1.1.1.1    -> 0x01010101u, port 53   -> 0x3500u
 */
#define IPV4_YANDEX_DNS     0x0808584Du
#define PORT_YANDEX_1253    0xE504u
#define IPV4_CLOUDFLARE_DNS 0x01010101u
#define PORT_DNS_53         0x3500u

const dpi_profile_t g_turkdpi_profiles[TURKDPI_NUM_PROFILES] = {
    /* [0] Standart Turkiye (Turk Telekom / TurkNet / Kablonet / Millenicom) */
    {
        .name      = "Standart Turkiye (TT / TurkNet / Kablonet - Hybrid SNI-Split + Ses)",
        .isp_hint  = "Turk Telekom, TurkNet, Kablonet, Millenicom, Netspeed",
        .do_passivedpi = 1,
        .do_block_quic = 1,
        .do_fragment_http = 1,
        .do_fragment_http_persistent = 1,
        .do_fragment_http_persistent_nowait = 1,
        .do_fragment_https = 1,
        .do_native_frag = 1,
        .do_reverse_frag = 1,
        .do_split_sni = 1,
        .do_host = 1,
        .do_host_removespace = 1,
        .do_fake_packet = 1,
        .fooling_flags = FOOL_BADSUM | FOOL_BADSEQ,
        .do_udp_fake = 1,
        .do_dnsv4_redirect = 1,
        .do_dnsv6_redirect = 1,
        .http_frag_size = 2,
        .https_frag_size = 2,
        .max_payload_size = 1200,
        .dnsv4_addr = IPV4_YANDEX_DNS,
        .dnsv4_port = PORT_YANDEX_1253,
        .dnsv6_addr = {0x2a,0x02,0x06,0xb8,0,0,0,0,0,0,0,0,0xfe,0xed,0x00,0xff},
        .dnsv6_port = PORT_YANDEX_1253,
    },
    /* [1] Superonline / Vodafone Modern (Zapret MD5Sig + Auto-TTL + SNI-Split) */
    {
        .name      = "Superonline & Vodafone Modern (Zapret MD5Sig + Auto-TTL + Ses)",
        .isp_hint  = "Turkcell Superonline, Vodafone Ev Interneti",
        .do_passivedpi = 1,
        .do_block_quic = 1,
        .do_fragment_http = 1,
        .do_fragment_http_persistent = 1,
        .do_fragment_http_persistent_nowait = 1,
        .do_fragment_https = 1,
        .do_native_frag = 1,
        .do_reverse_frag = 1,
        .do_split_sni = 1,
        .do_host = 1,
        .do_host_removespace = 1,
        .do_fake_packet = 1,
        .fooling_flags = FOOL_MD5SIG | FOOL_AUTOTTL | FOOL_BADSEQ,
        .auto_ttl_delta = 1,
        .auto_ttl_min = 3,
        .auto_ttl_max = 10,
        .do_udp_fake = 1,
        .do_dnsv4_redirect = 1,
        .do_dnsv6_redirect = 1,
        .http_frag_size = 2,
        .https_frag_size = 2,
        .max_payload_size = 1200,
        .dnsv4_addr = IPV4_YANDEX_DNS,
        .dnsv4_port = PORT_YANDEX_1253,
        .dnsv6_addr = {0x2a,0x02,0x06,0xb8,0,0,0,0,0,0,0,0,0xfe,0xed,0x00,0xff},
        .dnsv6_port = PORT_YANDEX_1253,
    },
    /* [2] Superonline Alternatif 1 (Auto-TTL 1-4-10 + BadSeq + Yandex DNS) */
    {
        .name      = "Superonline Alternatif 1 (Auto-TTL + BadSeq + Yandex DNS + Ses)",
        .isp_hint  = "Superonline Fiber / VDSL",
        .do_block_quic = 1,
        .do_fragment_http = 1,
        .do_fragment_http_persistent = 1,
        .do_fragment_http_persistent_nowait = 1,
        .do_fragment_https = 1,
        .do_native_frag = 1,
        .do_reverse_frag = 1,
        .do_split_sni = 1,
        .do_fake_packet = 1,
        .fooling_flags = FOOL_AUTOTTL | FOOL_BADSEQ,
        .auto_ttl_delta = 1,
        .auto_ttl_min = 3,
        .auto_ttl_max = 10,
        .do_udp_fake = 1,
        .do_dnsv4_redirect = 1,
        .do_dnsv6_redirect = 1,
        .http_frag_size = 2,
        .https_frag_size = 2,
        .max_payload_size = 1200,
        .dnsv4_addr = IPV4_YANDEX_DNS,
        .dnsv4_port = PORT_YANDEX_1253,
        .dnsv6_addr = {0x2a,0x02,0x06,0xb8,0,0,0,0,0,0,0,0,0xfe,0xed,0x00,0xff},
        .dnsv6_port = PORT_YANDEX_1253,
    },
    /* [3] Superonline Alternatif 2 (Sabit TTL 4 + BadSeq + Yandex DNS) */
    {
        .name      = "Superonline Alternatif 2 (Sabit TTL 4 + BadSeq + Yandex DNS)",
        .isp_hint  = "Superonline (4+ Hop Uzakliktaki Santraller)",
        .do_block_quic = 1,
        .do_fragment_http = 1,
        .do_fragment_http_persistent = 1,
        .do_fragment_http_persistent_nowait = 1,
        .do_fragment_https = 1,
        .do_native_frag = 1,
        .do_reverse_frag = 1,
        .do_split_sni = 1,
        .do_fake_packet = 1,
        .fooling_flags = FOOL_TTL | FOOL_BADSEQ,
        .fake_ttl = 4,
        .do_udp_fake = 1,
        .do_dnsv4_redirect = 1,
        .do_dnsv6_redirect = 1,
        .http_frag_size = 2,
        .https_frag_size = 2,
        .max_payload_size = 1200,
        .dnsv4_addr = IPV4_YANDEX_DNS,
        .dnsv4_port = PORT_YANDEX_1253,
        .dnsv6_addr = {0x2a,0x02,0x06,0xb8,0,0,0,0,0,0,0,0,0xfe,0xed,0x00,0xff},
        .dnsv6_port = PORT_YANDEX_1253,
    },
    /* [4] Superonline Alternatif 3 (Klasik TTL 3 + Yandex DNS) */
    {
        .name      = "Superonline Alternatif 3 (Klasik TTL 3 + Yandex DNS + Ses)",
        .isp_hint  = "Superonline Klasik Mod",
        .do_passivedpi = 1,
        .do_block_quic = 1,
        .do_fragment_http = 1,
        .do_fragment_http_persistent = 1,
        .do_fragment_http_persistent_nowait = 1,
        .do_fragment_https = 1,
        .do_native_frag = 1,
        .do_reverse_frag = 1,
        .do_split_sni = 1,
        .do_host = 1,
        .do_host_removespace = 1,
        .do_fake_packet = 1,
        .fooling_flags = FOOL_TTL,
        .fake_ttl = 3,
        .do_udp_fake = 1,
        .do_dnsv4_redirect = 1,
        .do_dnsv6_redirect = 1,
        .http_frag_size = 2,
        .https_frag_size = 40,
        .dnsv4_addr = IPV4_YANDEX_DNS,
        .dnsv4_port = PORT_YANDEX_1253,
        .dnsv6_addr = {0x2a,0x02,0x06,0xb8,0,0,0,0,0,0,0,0,0xfe,0xed,0x00,0xff},
        .dnsv6_port = PORT_YANDEX_1253,
    },
    /* [5] ByeDPI Saf SNI-Disorder (Sahte Paketsiz - Sifir Site Bozma / Oyun Modu) */
    {
        .name      = "ByeDPI Saf 3-Parca SNI-Disorder (Sahte Paketsiz - Oyun Modu)",
        .isp_hint  = "Hafif DPI Kullanan Tum ISS'ler (En Dusuk Gecikme)",
        .do_passivedpi = 1,
        .do_block_quic = 1,
        .do_fragment_http = 1,
        .do_fragment_http_persistent = 1,
        .do_fragment_http_persistent_nowait = 1,
        .do_fragment_https = 1,
        .do_native_frag = 1,
        .do_reverse_frag = 1,
        .do_split_sni = 1,
        .do_host = 1,
        .do_host_removespace = 1,
        .do_fake_packet = 0,
        .fooling_flags = FOOL_NONE,
        .do_udp_fake = 1,
        .do_dnsv4_redirect = 1,
        .do_dnsv6_redirect = 1,
        .http_frag_size = 2,
        .https_frag_size = 2,
        .max_payload_size = 1200,
        .dnsv4_addr = IPV4_YANDEX_DNS,
        .dnsv4_port = PORT_YANDEX_1253,
        .dnsv6_addr = {0x2a,0x02,0x06,0xb8,0,0,0,0,0,0,0,0,0xfe,0xed,0x00,0xff},
        .dnsv6_port = PORT_YANDEX_1253,
    },
    /* [6] Cloudflare DNS (1.1.1.1) + Hybrid MD5Sig/BadSum (Port 1253 Engelli Agler) */
    {
        .name      = "Cloudflare DNS (1.1.1.1) + Hybrid Desync (Yurt / Kampus / Kurumsal)",
        .isp_hint  = "Yandex Port 1253 Engelli Agler, Cloudflare DNS Kullananlar",
        .do_passivedpi = 1,
        .do_block_quic = 1,
        .do_fragment_http = 1,
        .do_fragment_http_persistent = 1,
        .do_fragment_http_persistent_nowait = 1,
        .do_fragment_https = 1,
        .do_native_frag = 1,
        .do_reverse_frag = 1,
        .do_split_sni = 1,
        .do_host = 1,
        .do_host_removespace = 1,
        .do_fake_packet = 1,
        .fooling_flags = FOOL_BADSUM | FOOL_BADSEQ | FOOL_MD5SIG,
        .do_udp_fake = 1,
        .do_dnsv4_redirect = 1,
        .do_dnsv6_redirect = 1,
        .http_frag_size = 2,
        .https_frag_size = 2,
        .max_payload_size = 1200,
        .dnsv4_addr = IPV4_CLOUDFLARE_DNS,
        .dnsv4_port = PORT_DNS_53,
        .dnsv6_addr = {0x26,0x06,0x47,0x00,0x47,0x00,0,0,0,0,0,0,0x00,0x00,0x11,0x11},
        .dnsv6_port = PORT_DNS_53,
    }
};

/* ============================================================================
 * 2. Decoy Templates (TLS ClientHello & HTTP GET)
 * ============================================================================ */
static const unsigned char g_default_fake_http[] =
    "GET / HTTP/1.1\r\n"
    "Host: www.iana.org\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n\r\n";

#define MAX_CUSTOM_FAKES 30
typedef struct {
    unsigned char *data;
    size_t         size;
} fake_blob_t;

static fake_blob_t g_fakes[MAX_CUSTOM_FAKES];
static size_t      g_fakes_count = 0;

int desync_add_custom_fake(unsigned char *data, size_t len) {
    if (g_fakes_count >= MAX_CUSTOM_FAKES) return -1;
    g_fakes[g_fakes_count].data = data;
    g_fakes[g_fakes_count].size = len;
    g_fakes_count++;
    return 0;
}

void desync_cleanup(void) {
    for (size_t i = 0; i < g_fakes_count; i++) {
        free(g_fakes[i].data);
        g_fakes[i].data = NULL;
        g_fakes[i].size = 0;
    }
    g_fakes_count = 0;
}

int desync_load_fake_hex(const char *hex_raw) {
    if (!hex_raw) return -1;
    size_t raw_size = strlen(hex_raw);
    if ((raw_size & 1) || raw_size == 0) return -2;

    size_t data_size = raw_size / 2;
    unsigned char *data = (unsigned char *)malloc(data_size);
    if (!data) return -3;

    for (size_t i = 0; i < raw_size; i += 2) {
        if (!isxdigit((unsigned char)hex_raw[i]) || !isxdigit((unsigned char)hex_raw[i + 1])) {
            free(data);
            return -4;
        }
        unsigned int b = 0;
        if (sscanf(hex_raw + i, "%2x", &b) != 1) {
            free(data);
            return -5;
        }
        data[i / 2] = (unsigned char)b;
    }
    if (desync_add_custom_fake(data, data_size) != 0) {
        free(data);
        return -6;
    }
    return 0;
}

int desync_load_fake_sni(const char *domain_name) {
    if (!domain_name) return -1;
    const size_t name_size = strlen(domain_name);
    if (name_size == 0 || name_size > 120) return -1;

    unsigned char *packet = (unsigned char *)calloc(1, 517);
    if (!packet) return -2;

    int built = probe_build_tls_client_hello(packet, 517, domain_name);
    if (built <= 0) {
        free(packet);
        return -1;
    }

    if (desync_add_custom_fake(packet, (size_t)built) != 0) {
        free(packet);
        return -3;
    }
    return 0;
}

void desync_init_defaults(void) {
    if (g_fakes_count == 0) {
        desync_load_fake_sni("www.microsoft.com");
    }
}

/* ============================================================================
 * 3. Multi-Fooling TCP Decoy Transmitter
 * ============================================================================ */
static int send_fake_payload(const HANDLE w_filter,
                             const WINDIVERT_ADDRESS *addr,
                             const char *pkt,
                             const UINT pktLen,
                             const BOOL is_ipv6,
                             const BYTE set_ttl,
                             const BYTE set_checksum,
                             const BYTE set_seq,
                             const BYTE set_md5sig,
                             const unsigned char *fake_data,
                             const size_t fake_size) {
    ALIGN64 char base_buf[MAX_PACKET_SIZE];
    ALIGN64 char batch_buf[4 * 1536];
    WINDIVERT_ADDRESS batch_addrs[4];
    UINT batch_bytes = 0;
    UINT batch_count = 0;

    PWINDIVERT_IPHDR   ip4  = NULL;
    PWINDIVERT_IPV6HDR ip6  = NULL;
    PWINDIVERT_TCPHDR  tcp  = NULL;
    PVOID              pld  = NULL;
    UINT               pld_len = 0;

    if (!WinDivertHelperParsePacket((PVOID)pkt, pktLen, &ip4, &ip6, NULL, NULL, NULL,
                                    &tcp, NULL, &pld, &pld_len, NULL, NULL)) {
        return -1;
    }
    if (!tcp || (!is_ipv6 && !ip4) || (is_ipv6 && !ip6)) {
        return -12;
    }

    UINT l3_l4_len = pld ? (UINT)((const char *)pld - pkt) : pktLen;
    UINT md5_opt_len = (set_md5sig && tcp->HdrLength <= 10) ? 20u : 0u;
    if (l3_l4_len + md5_opt_len + fake_size > sizeof(base_buf)) {
        return -13;
    }

    memcpy(base_buf, pkt, l3_l4_len);

    ptrdiff_t tcp_off = (const char *)tcp - pkt;
    PWINDIVERT_TCPHDR b_tcp = (PWINDIVERT_TCPHDR)(void *)(base_buf + tcp_off);

    /* Optional RFC 2385 TCP MD5 Signature Option (Kind=19, Len=18 + 2 NOPs = 20B) */
    if (md5_opt_len == 20u) {
        unsigned char *opt = (unsigned char *)base_buf + l3_l4_len;
        opt[0] = 19; /* TCP Option Kind 19: MD5 Signature */
        opt[1] = 18; /* Length: 18 bytes */
        /* 16-byte deterministic non-matching MD5 tag */
        for (int i = 0; i < 16; i++) opt[2 + i] = (unsigned char)(0xA5u ^ (i * 17u));
        opt[18] = 1; /* NOP */
        opt[19] = 1; /* NOP */
        b_tcp->HdrLength = (UINT16)(b_tcp->HdrLength + 5);
        l3_l4_len += 20u;
    }

    memcpy(base_buf + l3_l4_len, fake_data, fake_size);
    const UINT fake_len = l3_l4_len + (UINT)fake_size;

    PWINDIVERT_IPHDR   b_ip4 = is_ipv6 ? NULL : (PWINDIVERT_IPHDR)(void *)base_buf;
    PWINDIVERT_IPV6HDR b_ip6 = is_ipv6 ? (PWINDIVERT_IPV6HDR)(void *)base_buf : NULL;

    if (!is_ipv6) {
        b_ip4->Length = htons((uint16_t)fake_len);
    } else {
        b_ip6->Length = htons((uint16_t)(fake_len - sizeof(WINDIVERT_IPV6HDR)));
    }

    WINDIVERT_ADDRESS send_addr = *addr;
    WinDivertHelperCalcChecksums(base_buf, fake_len, &send_addr, (UINT64)0LL);

    ALIGN64 char var_buf[MAX_PACKET_SIZE];
    #define EMIT_VARIANT(v_ttl, v_badsum, v_badseq) do { \
        memcpy(var_buf, base_buf, fake_len); \
        PWINDIVERT_IPHDR   v_ip4 = is_ipv6 ? NULL : (PWINDIVERT_IPHDR)(void *)var_buf; \
        PWINDIVERT_IPV6HDR v_ip6 = is_ipv6 ? (PWINDIVERT_IPV6HDR)(void *)var_buf : NULL; \
        PWINDIVERT_TCPHDR  v_tcp = (PWINDIVERT_TCPHDR)(void *)(var_buf + tcp_off); \
        if ((v_ttl) != 0) { \
            if (!is_ipv6) { \
                uint16_t old_w, new_w; \
                memcpy(&old_w, &v_ip4->TTL, 2); \
                v_ip4->TTL = (BYTE)(v_ttl); \
                memcpy(&new_w, &v_ip4->TTL, 2); \
                v_ip4->Checksum = checksum_update_uint16(v_ip4->Checksum, old_w, new_w); \
            } else { \
                v_ip6->HopLimit = (BYTE)(v_ttl); \
            } \
        } \
        if (v_badseq) { \
            uint32_t old_seq = v_tcp->SeqNum; \
            uint32_t old_ack = v_tcp->AckNum; \
            uint32_t new_seq = htonl(ntohl(old_seq) - 10000u); \
            uint32_t new_ack = htonl(ntohl(old_ack) - 66000u); \
            v_tcp->SeqNum = new_seq; \
            v_tcp->AckNum = new_ack; \
            uint16_t c = checksum_update_uint32(v_tcp->Checksum, old_seq, new_seq); \
            v_tcp->Checksum = checksum_update_uint32(c, old_ack, new_ack); \
        } \
        if (v_badsum) { \
            v_tcp->Checksum = htons((uint16_t)(ntohs(v_tcp->Checksum) - 1u)); \
        } \
        if (fake_len <= 1536 && batch_count < 4) { \
            memcpy(batch_buf + batch_bytes, var_buf, fake_len); \
            batch_addrs[batch_count++] = send_addr; \
            batch_bytes += fake_len; \
        } else { \
            if (!WinDivertSend(w_filter, var_buf, fake_len, NULL, &send_addr)) return -3; \
        } \
    } while (0)

    if (set_ttl && set_checksum && set_seq) {
        EMIT_VARIANT(set_ttl, 1, 0);
        EMIT_VARIANT(0,       1, 1);
        EMIT_VARIANT(set_ttl, 0, 1);
    } else if (set_ttl && set_checksum) {
        EMIT_VARIANT(0,       1, 0);
        EMIT_VARIANT(set_ttl, 0, 0);
    } else if (set_ttl && set_seq) {
        EMIT_VARIANT(0,       0, 1);
        EMIT_VARIANT(set_ttl, 0, 0);
    } else if (set_checksum && set_seq) {
        EMIT_VARIANT(0,       1, 0);
        EMIT_VARIANT(0,       0, 1);
    } else {
        EMIT_VARIANT(set_ttl, set_checksum, set_seq);
    }

    #undef EMIT_VARIANT

    if (batch_count == 1) {
        if (!WinDivertSend(w_filter, batch_buf, batch_bytes, NULL, &batch_addrs[0]))
            return -3;
    } else if (batch_count > 1) {
        if (!WinDivertSendEx(w_filter, batch_buf, batch_bytes, NULL, 0,
                             batch_addrs, batch_count * (UINT)sizeof(WINDIVERT_ADDRESS), NULL))
            return -3;
    }
    return 0;
}

int desync_send_fake_tcp(const void *w_filter,
                         const void *addr_ptr,
                         const char *pkt,
                         unsigned int pktLen,
                         int is_ipv6,
                         uint8_t set_ttl,
                         uint8_t fooling_flags,
                         int is_https) {
    const WINDIVERT_ADDRESS *addr = (const WINDIVERT_ADDRESS *)addr_ptr;
    const BYTE badsum = (fooling_flags & FOOL_BADSUM) ? 1 : 0;
    const BYTE badseq = (fooling_flags & FOOL_BADSEQ) ? 1 : 0;
    const BYTE md5sig = (fooling_flags & FOOL_MD5SIG) ? 1 : 0;

    if (!set_ttl && !badsum && !badseq && !md5sig) return -1;

    if (!is_https) {
        return send_fake_payload((HANDLE)(uintptr_t)w_filter, addr, pkt, (UINT)pktLen, (BOOL)is_ipv6,
                                 set_ttl, badsum, badseq, md5sig,
                                 g_default_fake_http, sizeof(g_default_fake_http) - 1);
    }

    if (g_fakes_count == 0) {
        desync_init_defaults();
    }
    for (size_t i = 0; i < g_fakes_count; i++) {
        if (send_fake_payload((HANDLE)(uintptr_t)w_filter, addr, pkt, (UINT)pktLen, (BOOL)is_ipv6,
                              set_ttl, badsum, badseq, md5sig,
                              g_fakes[i].data, g_fakes[i].size) != 0) {
            return -1;
        }
    }
    return 0;
}

/* ============================================================================
 * 4. SNI-Midpoint Multi-Split & Reverse Disorder TCP Fragmenter
 * ============================================================================ */
static void build_tcp_segment(char *dst,
                              const char *orig_pkt,
                              UINT l3_l4_len,
                              ptrdiff_t tcp_off,
                              BOOL is_ipv6,
                              const char *seg_payload,
                              UINT seg_len,
                              uint32_t seq_offset,
                              const WINDIVERT_ADDRESS *base_addr,
                              WINDIVERT_ADDRESS *out_addr,
                              UINT *out_len) {
    ALIGN64 char aligned_seg[MAX_PACKET_SIZE];
    memcpy(aligned_seg, orig_pkt, l3_l4_len);
    memcpy(aligned_seg + l3_l4_len, seg_payload, seg_len);
    UINT total_len = l3_l4_len + seg_len;

    if (!is_ipv6) {
        PWINDIVERT_IPHDR ip4 = (PWINDIVERT_IPHDR)(void *)aligned_seg;
        ip4->Length = htons((uint16_t)total_len);
    } else {
        PWINDIVERT_IPV6HDR ip6 = (PWINDIVERT_IPV6HDR)(void *)aligned_seg;
        ip6->Length = htons((uint16_t)(total_len - sizeof(WINDIVERT_IPV6HDR)));
    }

    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(void *)(aligned_seg + tcp_off);
    if (seq_offset > 0) {
        tcp->SeqNum = htonl(ntohl(tcp->SeqNum) + seq_offset);
    }

    *out_addr = *base_addr;
    *out_len  = total_len;
    WinDivertHelperCalcChecksums(aligned_seg, total_len, out_addr, (UINT64)0LL);
    memcpy(dst, aligned_seg, total_len);
}

int desync_send_tcp_split(void *w_filter,
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
                          int reverse_order) {
    (void)packet_v4; (void)ppIpHdr; (void)ppIpV6Hdr;

    if (!split_pos1 || split_pos1 >= packet_dataLen || !addr_ptr) return -1;

    WINDIVERT_ADDRESS addr = *(const WINDIVERT_ADDRESS *)addr_ptr;
    ALIGN64 char seg_buf[3 * MAX_PACKET_SIZE];
    WINDIVERT_ADDRESS seg_addrs[3];
    UINT seg_lens[3] = {0, 0, 0};

    const UINT l3_l4_len = packetLen - packet_dataLen;
    const ptrdiff_t tcp_off = (const char *)ppTcpHdr - packet;
    const BOOL is_v6 = (BOOL)(packet_v6 != 0);
    const char *pld = (const char *)packet_data;

    /* 3-way Multi-Split (e.g. [0..2], [2..sni_mid], [sni_mid..end]) */
    if (split_pos2 > split_pos1 && split_pos2 < packet_dataLen &&
        (l3_l4_len + packet_dataLen <= MAX_PACKET_SIZE)) {
        UINT len0 = split_pos1;
        UINT len1 = split_pos2 - split_pos1;
        UINT len2 = packet_dataLen - split_pos2;

        if (!reverse_order) {
            build_tcp_segment(seg_buf, packet, l3_l4_len, tcp_off, is_v6,
                              pld, len0, 0, &addr, &seg_addrs[0], &seg_lens[0]);
            build_tcp_segment(seg_buf + seg_lens[0], packet, l3_l4_len, tcp_off, is_v6,
                              pld + split_pos1, len1, split_pos1, &addr, &seg_addrs[1], &seg_lens[1]);
            build_tcp_segment(seg_buf + seg_lens[0] + seg_lens[1], packet, l3_l4_len, tcp_off, is_v6,
                              pld + split_pos2, len2, split_pos2, &addr, &seg_addrs[2], &seg_lens[2]);
        } else {
            /* Reverse Disorder: Segment 2 (sni_mid..end) -> Segment 1 (2..sni_mid) -> Segment 0 (0..2) */
            build_tcp_segment(seg_buf, packet, l3_l4_len, tcp_off, is_v6,
                              pld + split_pos2, len2, split_pos2, &addr, &seg_addrs[0], &seg_lens[0]);
            build_tcp_segment(seg_buf + seg_lens[0], packet, l3_l4_len, tcp_off, is_v6,
                              pld + split_pos1, len1, split_pos1, &addr, &seg_addrs[1], &seg_lens[1]);
            build_tcp_segment(seg_buf + seg_lens[0] + seg_lens[1], packet, l3_l4_len, tcp_off, is_v6,
                              pld, len0, 0, &addr, &seg_addrs[2], &seg_lens[2]);
        }

        WinDivertSendEx((HANDLE)w_filter, seg_buf, seg_lens[0] + seg_lens[1] + seg_lens[2],
                        NULL, 0, seg_addrs, 3 * (UINT)sizeof(WINDIVERT_ADDRESS), NULL);
        return 0;
    }

    /* 2-way Split ([0..split_pos1], [split_pos1..end]) */
    UINT len0 = split_pos1;
    UINT len1 = packet_dataLen - split_pos1;

    if (!reverse_order) {
        build_tcp_segment(seg_buf, packet, l3_l4_len, tcp_off, is_v6,
                          pld, len0, 0, &addr, &seg_addrs[0], &seg_lens[0]);
        build_tcp_segment(seg_buf + seg_lens[0], packet, l3_l4_len, tcp_off, is_v6,
                          pld + split_pos1, len1, split_pos1, &addr, &seg_addrs[1], &seg_lens[1]);
    } else {
        build_tcp_segment(seg_buf, packet, l3_l4_len, tcp_off, is_v6,
                          pld + split_pos1, len1, split_pos1, &addr, &seg_addrs[0], &seg_lens[0]);
        build_tcp_segment(seg_buf + seg_lens[0], packet, l3_l4_len, tcp_off, is_v6,
                          pld, len0, 0, &addr, &seg_addrs[1], &seg_lens[1]);
    }

    WinDivertSendEx((HANDLE)w_filter, seg_buf, seg_lens[0] + seg_lens[1],
                    NULL, 0, seg_addrs, 2 * (UINT)sizeof(WINDIVERT_ADDRESS), NULL);
    return 0;
}

/* ============================================================================
 * 5. Discord Voice / WebRTC UDP Desync (Low-TTL UDP Decoy)
 * ============================================================================ */
int desync_is_discord_or_webrtc_udp(uint16_t srcport_net, uint16_t dstport_net,
                                    const unsigned char *pld, unsigned int pld_len) {
    if (!pld || pld_len < 16) return 0;

    uint16_t sport = ntohs(srcport_net);
    uint16_t dport = ntohs(dstport_net);
    if (sport < 1024 || dport == 53 || dport == 443 || dport == 1253) return 0;

    /* 1. Discord Voice IP Discovery (70 or 74 bytes starting with 0x00 0x01 0x00 0x46) */
    if ((pld_len == 70 || pld_len == 74) &&
        pld[0] == 0x00 && pld[1] == 0x01 && pld[2] == 0x00 && (pld[3] == 0x46 || pld[3] == 0x42)) {
        return 1;
    }

    /* 2. RFC 5389 STUN Binding Request (Magic Cookie 0x2112A442 at offset 4) */
    if (pld_len >= 20 && (pld[0] & 0xC0) == 0x00 &&
        pld[4] == 0x21 && pld[5] == 0x12 && pld[6] == 0xA4 && pld[7] == 0x42) {
        return 1;
    }

    /* 3. WebRTC DTLS 1.2 / 1.3 Handshake (ContentType 22 = 0x16, Version 0xFEFF / 0xFEFD) */
    if (pld_len >= 25 && pld[0] == 0x16 && pld[1] == 0xFE && (pld[2] == 0xFF || pld[2] == 0xFD)) {
        return 1;
    }

    /* 4. High Discord Voice UDP port range (50000 - 65535) initial packet */
    if (dport >= 50000 && pld_len >= 24 && pld_len <= 128 && pld[0] == 0x00) {
        return 1;
    }

    return 0;
}

int desync_send_udp_fake(void *w_filter,
                         const void *addr_ptr,
                         const char *pkt,
                         unsigned int pktLen,
                         int is_ipv6) {
    ALIGN64 char decoy_buf[128];
    const WINDIVERT_ADDRESS *addr = (const WINDIVERT_ADDRESS *)addr_ptr;
    PWINDIVERT_IPHDR   ip4 = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    PWINDIVERT_UDPHDR  udp = NULL;
    PVOID              pld = NULL;
    UINT               pld_len = 0;

    if (!WinDivertHelperParsePacket((PVOID)pkt, (UINT)pktLen, &ip4, &ip6, NULL, NULL, NULL,
                                    NULL, &udp, &pld, &pld_len, NULL, NULL)) {
        return -1;
    }
    if (!udp || (!is_ipv6 && !ip4) || (is_ipv6 && !ip6)) return -1;

    UINT l3_l4_len = pld ? (UINT)((const char *)pld - pkt) : (UINT)pktLen;
    if (l3_l4_len + 8 > sizeof(decoy_buf)) return -1;

    memcpy(decoy_buf, pkt, l3_l4_len);
    memset(decoy_buf + l3_l4_len, 0, 8);
    UINT decoy_len = l3_l4_len + 8;

    ptrdiff_t udp_off = (const char *)udp - pkt;
    PWINDIVERT_UDPHDR d_udp = (PWINDIVERT_UDPHDR)(void *)(decoy_buf + udp_off);
    d_udp->Length = htons((uint16_t)(sizeof(WINDIVERT_UDPHDR) + 8));

    if (!is_ipv6) {
        PWINDIVERT_IPHDR d_ip4 = (PWINDIVERT_IPHDR)(void *)decoy_buf;
        d_ip4->Length = htons((uint16_t)decoy_len);
        d_ip4->TTL    = 3;
    } else {
        PWINDIVERT_IPV6HDR d_ip6 = (PWINDIVERT_IPV6HDR)(void *)decoy_buf;
        d_ip6->Length   = htons((uint16_t)(decoy_len - sizeof(WINDIVERT_IPV6HDR)));
        d_ip6->HopLimit = 3;
    }

    WINDIVERT_ADDRESS send_addr = *addr;
    WinDivertHelperCalcChecksums(decoy_buf, decoy_len, &send_addr, (UINT64)0LL);
    /* Corrupt UDP checksum by 1 so even if TTL=3 reaches a local relay it is discarded */
    d_udp->Checksum = udp_checksum_fix_zero(htons((uint16_t)(ntohs(d_udp->Checksum) - 1u)));

    return WinDivertSend((HANDLE)w_filter, decoy_buf, decoy_len, NULL, &send_addr) ? 0 : -2;
}

/* ============================================================================
 * 6. Backward-Compatible Wrappers for Legacy Unit Tests
 * ============================================================================ */
int send_fake_http_request(const HANDLE w_filter,
                           const PWINDIVERT_ADDRESS addr,
                           const char *pkt,
                           const UINT packetLen,
                           const BOOL is_ipv6,
                           const BYTE set_ttl,
                           const BYTE set_checksum,
                           const BYTE set_seq) {
    uint8_t flags = (set_checksum ? FOOL_BADSUM : 0) | (set_seq ? FOOL_BADSEQ : 0);
    return desync_send_fake_tcp(w_filter, addr, pkt, packetLen, is_ipv6, set_ttl, flags, 0);
}

int send_fake_https_request(const HANDLE w_filter,
                            const PWINDIVERT_ADDRESS addr,
                            const char *pkt,
                            const UINT packetLen,
                            const BOOL is_ipv6,
                            const BYTE set_ttl,
                            const BYTE set_checksum,
                            const BYTE set_seq) {
    uint8_t flags = (set_checksum ? FOOL_BADSUM : 0) | (set_seq ? FOOL_BADSEQ : 0);
    return desync_send_fake_tcp(w_filter, addr, pkt, packetLen, is_ipv6, set_ttl, flags, 1);
}

int fake_load_from_hex(const char *packet_raw) { return desync_load_fake_hex(packet_raw); }
int fake_load_from_sni(const char *domain_name) { return desync_load_fake_sni(domain_name); }
void fake_load_default(void) { desync_init_defaults(); }
