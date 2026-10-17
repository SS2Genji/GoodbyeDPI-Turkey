/**
 * TurkDPI — Native In-Process ISP Auto-Probe & TLS 1.3 Handshake Verifier
 *
 * Eliminates fragile batch-script curl.exe loops and poisoned OS DNS caches:
 *   1. Resolves discord.com directly via Yandex Non-Standard DNS (77.88.8.8:1253)
 *      with fallback to Cloudflare anycast IPs (162.159.135.232 / 162.159.136.232).
 *   2. Hot-swaps the active DPI profile in memory while the WinDivert thread runs.
 *   3. Performs a non-blocking TCP + TLS 1.3 ClientHello (SNI=discord.com &
 *      SNI=gateway.discord.gg) and verifies a real TLS ServerHello (0x16 0x03 .. 0x02)
 *      plus a sanity check on www.google.com so normal sites never break.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <windows.h>
#include "turkdpi.h"

/* ============================================================================
 * 1. Minimal RFC 1035 Raw DNS Query Builder & A-Record Parser
 * ============================================================================ */
int probe_build_dns_query(unsigned char *buf, size_t max_len, const char *domain, uint16_t txid) {
    if (!buf || !domain) return -1;
    size_t dlen = strlen(domain);
    if (dlen == 0 || dlen > HOST_MAXLEN || max_len < 12 + dlen + 2 + 4) return -1;

    /* 12-byte DNS Header: Standard Query, RD=1, QDCOUNT=1 */
    buf[0] = (unsigned char)(txid >> 8);
    buf[1] = (unsigned char)(txid & 0xFF);
    buf[2] = 0x01; buf[3] = 0x00; /* Flags: 0x0100 (Recursion Desired) */
    buf[4] = 0x00; buf[5] = 0x01; /* QDCOUNT = 1 */
    buf[6] = 0x00; buf[7] = 0x00; /* ANCOUNT = 0 */
    buf[8] = 0x00; buf[9] = 0x00; /* NSCOUNT = 0 */
    buf[10] = 0x00; buf[11] = 0x00; /* ARCOUNT = 0 */

    size_t pos = 12;
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);
        if (label_len == 0 || label_len > 63 || pos + 1 + label_len >= max_len) return -1;
        buf[pos++] = (unsigned char)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;
        if (!dot) break;
        p = dot + 1;
    }
    buf[pos++] = 0x00; /* Root label */
    buf[pos++] = 0x00; buf[pos++] = 0x01; /* QTYPE = A (1) */
    buf[pos++] = 0x00; buf[pos++] = 0x01; /* QCLASS = IN (1) */
    return (int)pos;
}

static size_t skip_dns_name(const unsigned char *buf, size_t len, size_t pos) {
    size_t jumps = 0;
    while (pos < len && jumps < 32) {
        unsigned char c = buf[pos];
        if (c == 0) return pos + 1;
        if ((c & 0xC0) == 0xC0) {
            if (pos + 2 > len) return len + 1;
            return pos + 2;
        }
        pos += 1 + c;
        jumps++;
    }
    return len + 1;
}

static int is_valid_public_ipv4(uint32_t ip_net) {
    const unsigned char *b = (const unsigned char *)&ip_net;
    if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224) return 0;
    if (b[0] == 192 && b[1] == 168) return 0;
    if (b[0] == 172 && (b[1] >= 16 && b[1] <= 31)) return 0;
    /* Reject known Turkish ISP / BTK block-page sinkhole subnet 195.175.254.0/24 */
    if (b[0] == 195 && b[1] == 175 && b[2] == 254) return 0;
    return 1;
}

uint32_t probe_parse_dns_a_record(const unsigned char *buf, size_t len, uint16_t expected_txid) {
    if (!buf || len < 12) return 0;
    uint16_t txid = (uint16_t)(((unsigned int)buf[0] << 8) | buf[1]);
    if (txid != expected_txid) return 0;
    if ((buf[2] & 0x80) == 0 || (buf[3] & 0x0F) != 0) return 0; /* Must be QR=1, RCODE=0 */

    uint16_t qdcount = (uint16_t)(((unsigned int)buf[4] << 8) | buf[5]);
    uint16_t ancount = (uint16_t)(((unsigned int)buf[6] << 8) | buf[7]);
    if (ancount == 0) return 0;

    size_t pos = 12;
    for (uint16_t i = 0; i < qdcount; i++) {
        pos = skip_dns_name(buf, len, pos);
        if (pos + 4 > len) return 0;
        pos += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        pos = skip_dns_name(buf, len, pos);
        if (pos + 10 > len) return 0;
        uint16_t rtype  = (uint16_t)(((unsigned int)buf[pos] << 8) | buf[pos + 1]);
        uint16_t rclass = (uint16_t)(((unsigned int)buf[pos + 2] << 8) | buf[pos + 3]);
        uint16_t rdlen  = (uint16_t)(((unsigned int)buf[pos + 8] << 8) | buf[pos + 9]);
        pos += 10;
        if (pos + rdlen > len) return 0;
        if (rtype == 1 && rclass == 1 && rdlen == 4) {
            uint32_t ip_net;
            memcpy(&ip_net, buf + pos, 4);
            if (is_valid_public_ipv4(ip_net)) {
                return ip_net;
            }
        }
        pos += rdlen;
    }
    return 0;
}

/* ============================================================================
 * 2. Minimal Realistic TLS 1.2 / 1.3 ClientHello Builder for Probing
 * ============================================================================ */
int probe_build_tls_client_hello(unsigned char *buf, size_t max_len, const char *sni_host) {
    if (!buf || !sni_host) return -1;
    size_t sni_len = strlen(sni_host);
    if (sni_len == 0 || sni_len > HOST_MAXLEN) return -1;

    /* Extensions:
     *   - server_name (0x0000): 4 + 5 + sni_len = 9 + sni_len
     *   - supported_groups (0x000a): 12 bytes
     *   - ec_point_formats (0x000b): 6 bytes
     *   - signature_algorithms (0x000d): 18 bytes
     *   - alpn (0x0010): 18 bytes
     *   - supported_versions (0x002b): 9 bytes
     *   - psk_key_exchange_modes (0x002d): 6 bytes
     *   - key_share (0x0033): 42 bytes
     */
    const size_t ext_sni_len = 9 + sni_len;
    static const unsigned char ext_tail[] = {
        /* supported_groups (x25519, secp256r1, secp384r1) */
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
        /* ec_point_formats */
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        /* signature_algorithms */
        0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0c,
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
        /* ALPN (h2, http/1.1) */
        0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c,
        0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
        /* supported_versions (TLS 1.3, TLS 1.2) */
        0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03,
        /* psk_key_exchange_modes */
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
        /* key_share (x25519 32-byte public key) */
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
        0x3a, 0x51, 0x9c, 0x42, 0x7b, 0x11, 0x8e, 0x20, 0x6f, 0x45, 0x12, 0x88, 0x91, 0x3c, 0x4d, 0x5e,
        0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3, 0x04, 0x15, 0x26, 0x37, 0x48, 0x59
    };

    const size_t ext_total_len = ext_sni_len + sizeof(ext_tail);
    /* ClientHello body: Version(2) + Random(32) + SessionID(1+32) + Ciphers(2+18) + Comp(1+1) + ExtLen(2) + Ext */
    const size_t ch_body_len = 2 + 32 + 33 + 20 + 2 + 2 + ext_total_len;
    const size_t record_len  = 4 + ch_body_len;
    const size_t total_len   = 5 + record_len;

    if (total_len > max_len) return -1;

    size_t p = 0;
    /* TLS Record Header */
    buf[p++] = 0x16; /* Handshake */
    buf[p++] = 0x03; buf[p++] = 0x01; /* Legacy TLS 1.0 record version */
    buf[p++] = (unsigned char)(record_len >> 8);
    buf[p++] = (unsigned char)(record_len & 0xFF);

    /* Handshake Header: ClientHello (1) */
    buf[p++] = 0x01;
    buf[p++] = 0x00;
    buf[p++] = (unsigned char)(ch_body_len >> 8);
    buf[p++] = (unsigned char)(ch_body_len & 0xFF);

    /* Client Version: TLS 1.2 (0x0303) */
    buf[p++] = 0x03; buf[p++] = 0x03;

    /* 32-byte Client Random */
    uint64_t tick = GetTickCount64();
    for (size_t i = 0; i < 32; i++) {
        buf[p++] = (unsigned char)((tick >> ((i & 7) * 8)) ^ (0x5Au + i * 19u));
    }

    /* 32-byte Session ID (TLS 1.3 middlebox compatibility mode) */
    buf[p++] = 32;
    for (size_t i = 0; i < 32; i++) {
        buf[p++] = (unsigned char)(0xA3u ^ (i * 11u));
    }

    /* Cipher Suites (18 bytes = 9 suites) */
    static const unsigned char ciphers[18] = {
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, /* TLS 1.3 suites */
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8
    };
    buf[p++] = 0x00; buf[p++] = sizeof(ciphers);
    memcpy(buf + p, ciphers, sizeof(ciphers));
    p += sizeof(ciphers);

    /* Compression Methods (null) */
    buf[p++] = 0x01; buf[p++] = 0x00;

    /* Extensions Total Length */
    buf[p++] = (unsigned char)(ext_total_len >> 8);
    buf[p++] = (unsigned char)(ext_total_len & 0xFF);

    /* Extension 0x0000: server_name */
    buf[p++] = 0x00; buf[p++] = 0x00;
    buf[p++] = (unsigned char)((5 + sni_len) >> 8);
    buf[p++] = (unsigned char)((5 + sni_len) & 0xFF);
    buf[p++] = (unsigned char)((3 + sni_len) >> 8);
    buf[p++] = (unsigned char)((3 + sni_len) & 0xFF);
    buf[p++] = 0x00; /* host_name type */
    buf[p++] = (unsigned char)(sni_len >> 8);
    buf[p++] = (unsigned char)(sni_len & 0xFF);
    memcpy(buf + p, sni_host, sni_len);
    p += sni_len;

    /* Remaining TLS 1.3 / 1.2 Extensions */
    memcpy(buf + p, ext_tail, sizeof(ext_tail));
    p += sizeof(ext_tail);

    return (int)p;
}

/* ============================================================================
 * 3. Live WinSock2 Raw DNS Resolver & Non-Blocking TLS Handshake Probe
 * ============================================================================ */
#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)

static void ensure_winsock_initialized(void) {
    static int wsa_ready = 0;
    if (!wsa_ready) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
            wsa_ready = 1;
        }
    }
}

static uint32_t query_dns_udp_single(uint32_t dns_ip_net, uint16_t dns_port_host,
                                     const char *domain, int timeout_ms) {
    ensure_winsock_initialized();
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;

    DWORD tv = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = dns_ip_net;
    sin.sin_port        = htons(dns_port_host);

    uint16_t txid = (uint16_t)(GetTickCount64() ^ 0x5A3Cu);
    unsigned char qbuf[512];
    int qlen = probe_build_dns_query(qbuf, sizeof(qbuf), domain, txid);
    if (qlen <= 0) {
        closesocket(s);
        return 0;
    }

    if (sendto(s, (const char *)qbuf, qlen, 0, (struct sockaddr *)&sin, sizeof(sin)) != qlen) {
        closesocket(s);
        return 0;
    }

    unsigned char rbuf[512];
    int rlen = recvfrom(s, (char *)rbuf, sizeof(rbuf), 0, NULL, NULL);
    closesocket(s);
    if (rlen <= 0) return 0;

    return probe_parse_dns_a_record(rbuf, (size_t)rlen, txid);
}

uint32_t probe_resolve_domain(const char *domain, uint32_t fallback_ip_net) {
    flush_dns_cache();

    /* 1. Try Yandex Non-Standard Port 77.88.8.8:1253 (bypasses ISP UDP 53 interception) */
    uint32_t ip = query_dns_udp_single(0x0808584Du, 1253, domain, 600);
    if (ip != 0) return ip;

    /* 2. Try Cloudflare 1.1.1.1:53 (redirected by our active WinDivert DNS engine) */
    ip = query_dns_udp_single(0x01010101u, 53, domain, 600);
    if (ip != 0) return ip;

    /* 3. Try Google 8.8.8.8:53 */
    ip = query_dns_udp_single(0x08080808u, 53, domain, 600);
    if (ip != 0) return ip;

    /* 4. Guaranteed Cloudflare/Google Anycast Fallback IP */
    return fallback_ip_net;
}

int probe_test_https_target(uint32_t ip_net, uint16_t port_host, const char *sni_host, int timeout_ms) {
    ensure_winsock_initialized();
    uint64_t t_start = GetTickCount64();

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    /* Enable non-blocking mode for precise timeout control */
    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = ip_net;
    sin.sin_port        = htons(port_host);

    int rc = connect(s, (struct sockaddr *)&sin, sizeof(sin));
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(s);
        return 0;
    }

    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_SET(s, &wfds);
    FD_ZERO(&efds); FD_SET(s, &efds);
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(0, NULL, &wfds, &efds, &tv);
    if (rc <= 0 || FD_ISSET(s, &efds) || !FD_ISSET(s, &wfds)) {
        closesocket(s);
        return 0;
    }

    int so_err = 0;
    int so_len = sizeof(so_err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_err, &so_len);
    if (so_err != 0) {
        closesocket(s);
        return 0;
    }

    /* Switch back to blocking with socket timeout for TLS ClientHello -> ServerHello */
    nonblock = 0;
    ioctlsocket(s, FIONBIO, &nonblock);
    uint64_t elapsed = GetTickCount64() - t_start;
    DWORD rem_ms = (elapsed < (uint64_t)timeout_ms) ? (DWORD)((uint64_t)timeout_ms - elapsed) : 400;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&rem_ms, sizeof(rem_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&rem_ms, sizeof(rem_ms));

    unsigned char ch_buf[512];
    int ch_len = probe_build_tls_client_hello(ch_buf, sizeof(ch_buf), sni_host);
    if (ch_len <= 0 || send(s, (const char *)ch_buf, ch_len, 0) != ch_len) {
        closesocket(s);
        return 0;
    }

    unsigned char resp[64];
    int rlen = recv(s, (char *)resp, sizeof(resp), 0);
    closesocket(s);

    /* Verify valid TLS Handshake record (0x16 0x03 0x01..0x03) with ServerHello (0x02 at byte 5) */
    if (rlen >= 6 && resp[0] == 0x16 && resp[1] == 0x03 && resp[5] == 0x02) {
        int total_ms = (int)(GetTickCount64() - t_start);
        return total_ms > 0 ? total_ms : 1;
    }
    return 0;
}

/* Discord Cloudflare anycast IPs: 162.159.135.232 (0xE8879FA2) & 162.159.136.232 (0xE8889FA2)
 * Google anycast IP: 142.250.187.196 (0xC4BBFA8E) */
#define FALLBACK_DISCORD_IP 0xE8879FA2u
#define FALLBACK_GATEWAY_IP 0xE8889FA2u
#define FALLBACK_GOOGLE_IP  0xC4BBFA8Eu

int probe_find_best_profile(volatile const dpi_profile_t **active_profile_ptr) {
    /* Probe order:
     *   0 -> Standart Turkiye (TT / TurkNet / Kablonet - Hybrid SNI-Split + BadSum/Seq)
     *   1 -> Superonline & Vodafone Modern (Zapret MD5Sig + Auto-TTL + SNI-Split)
     *   5 -> ByeDPI Saf 3-Parca SNI-Disorder (Sahte Paketsiz - Oyun Modu)
     *   2 -> Superonline Alternatif 1 (Auto-TTL + BadSeq)
     *   6 -> Cloudflare DNS (1.1.1.1) + Hybrid Desync
     *   3 -> Superonline Alternatif 2 (Sabit TTL 4 + BadSeq)
     *   4 -> Superonline Alternatif 3 (Klasik TTL 3)
     */
    static const int probe_order[TURKDPI_NUM_PROFILES] = { 0, 1, 5, 2, 6, 3, 4 };

    printf("\n============================================================================\n");
    printf("  [*] TurkDPI Otomatik ISS & DPI Analiz Motoru Baslatiliyor...\n");
    printf("============================================================================\n");

    /* Temporarily activate Profile 0 so DNS redirector is live during IP resolution */
    *active_profile_ptr = &g_turkdpi_profiles[0];
    Sleep(150);

    uint32_t discord_ip = probe_resolve_domain("discord.com", FALLBACK_DISCORD_IP);
    uint32_t gateway_ip = probe_resolve_domain("gateway.discord.gg", FALLBACK_GATEWAY_IP);
    uint32_t google_ip  = probe_resolve_domain("www.google.com", FALLBACK_GOOGLE_IP);

    const unsigned char *dip = (const unsigned char *)&discord_ip;
    printf("  [+] Hedef Cozumlendi: discord.com -> %u.%u.%u.%u:443 (TLS 1.3 SNI Probe)\n\n",
           dip[0], dip[1], dip[2], dip[3]);

    for (int i = 0; i < TURKDPI_NUM_PROFILES; i++) {
        int pidx = probe_order[i];
        const dpi_profile_t *prof = &g_turkdpi_profiles[pidx];

        *active_profile_ptr = prof;
        flush_dns_cache();
        Sleep(80);

        printf("  [Test %d/%d] Profil [%d]: %s\n", i + 1, TURKDPI_NUM_PROFILES, pidx, prof->name);
        printf("             Hedef ISS : %s\n", prof->isp_hint);

        int ms_discord = probe_test_https_target(discord_ip, 443, "discord.com", 1500);
        if (ms_discord <= 0) {
            /* Retry once on alternate Cloudflare anycast IP */
            ms_discord = probe_test_https_target(FALLBACK_GATEWAY_IP, 443, "discord.com", 1500);
        }

        if (ms_discord > 0) {
            int ms_gateway = probe_test_https_target(gateway_ip, 443, "gateway.discord.gg", 1500);
            int ms_google  = probe_test_https_target(google_ip, 443, "www.google.com", 1500);

            if (ms_gateway > 0 && ms_google > 0) {
                printf("             Sonuc     : [BASARILI] Discord TLS=%dms | Gateway=%dms | Google=%dms\n\n",
                       ms_discord, ms_gateway, ms_google);
                printf("============================================================================\n");
                printf("  [+] EN UYGUN PROFIL BULUNDU: [Profil %d] %s\n", pidx, prof->name);
                printf("============================================================================\n");
                return pidx;
            }
        }
        printf("             Sonuc     : [ENGELLENDI / ZAMAN ASIMI] Sonraki stratejiye geciliyor...\n\n");
    }

    /* Default to Profile 0 if offline or firewall blocks socket probe */
    *active_profile_ptr = &g_turkdpi_profiles[0];
    printf("  [!] Dogrudan TLS testi yanit alamadi; Varsayilan [Profil 0] aktif edildi.\n");
    return 0;
}

#else

uint32_t probe_resolve_domain(const char *domain, uint32_t fallback_ip_net) {
    (void)domain;
    return fallback_ip_net;
}

int probe_test_https_target(uint32_t ip_net, uint16_t port_host, const char *sni_host, int timeout_ms) {
    (void)ip_net; (void)port_host; (void)sni_host; (void)timeout_ms;
    return 25;
}

int probe_find_best_profile(volatile const dpi_profile_t **active_profile_ptr) {
    if (active_profile_ptr) *active_profile_ptr = &g_turkdpi_profiles[0];
    return 0;
}

#endif
