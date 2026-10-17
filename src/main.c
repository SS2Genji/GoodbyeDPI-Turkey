/**
 * TurkDPI — High-Performance Next-Gen DPI Circumvention Engine for Turkey
 *
 * Clean-sheet architecture combining:
 *   - Hardware SIMD (SSE2 / SSE4.2 CRC32C) & RFC 1624 O(1) differential checksums
 *   - Zapret + ByeDPI + GoodbyeDPI multi-strategy desynchronization:
 *       * 3-Way SNI-Midpoint Split & Reverse Disorder
 *       * TCP MD5Sig (RFC 2385 Option 19) + BadSeq + BadSum + Smart Auto-TTL decoys
 *       * Discord Voice / WebRTC UDP low-TTL pinhole desync
 *   - Dual-Stack DNS Hijack Shield (77.88.8.8:1253 + IPv6 fe80::1 router leak blocker)
 *   - Built-in In-Process TLS 1.3 ISP Auto-Probe, UAC Auto-Elevation, Windows Service
 *     Installer/Uninstaller, and Interactive Turkish Console UI
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#endif
#include <windows.h>
#include "windivert.h"
#include "turkdpi.h"

#define SERVICE_NAME "GoodbyeDPI"

/* Global active profile pointer (atomically swapped during --auto probe) */
static dpi_profile_t g_custom_profile;
static volatile const dpi_profile_t *g_active_profile = &g_turkdpi_profiles[0];
static volatile int g_exiting = 0;
static HANDLE g_w_filter = INVALID_HANDLE_VALUE;
static HANDLE g_quic_filter = INVALID_HANDLE_VALUE;

/* Comprehensive WinDivert filter covering:
 *   - Inbound TCP 80/443 (SYN+ACK, RST, FIN, HTTP 302 Redirect)
 *   - Outbound TCP 80/443 (SYN, HTTP GET, TLS ClientHello)
 *   - Inbound/Outbound UDP 53 & 1253 (Dual-Stack DNS Redirection + IPv6 Router DNS Leak Shield)
 *   - Outbound UDP 443 (QUIC Block) & High UDP ports (Discord Voice / WebRTC STUN/DTLS Desync)
 */
#define TURKDPI_MAIN_FILTER \
    "(tcp and !impostor and !loopback and " \
    "((inbound and (tcp.SrcPort == 80 or tcp.SrcPort == 443)) or " \
    "(outbound and (tcp.DstPort == 80 or tcp.DstPort == 443)))) or " \
    "(udp and !impostor and !loopback and " \
    "((outbound and (udp.DstPort == 53 or udp.DstPort == 443 or udp.DstPort == 1253 or " \
    "(udp.SrcPort >= 1024 and udp.DstPort >= 19294 and udp.PayloadLength >= 16 and udp.PayloadLength <= 160))) or " \
    "(inbound and (udp.SrcPort == 53 or udp.SrcPort == 1253))))"

static const char *http_methods[] = {
    "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ",
};

/* ============================================================================
 * 1. HTTP & Packet Header Helpers
 * ============================================================================ */
static void mix_case(char *pktdata, unsigned int pktlen) {
    if (pktlen <= 0) return;
    for (unsigned int i = 0; i < pktlen; i++) {
        if (i & 1) pktdata[i] = (char)toupper((unsigned char)pktdata[i]);
    }
}

static int is_passivedpi_redirect(const char *pktdata, unsigned int pktlen) {
    if (pktlen < 16) return 0;
    if (memcmp(pktdata, "HTTP/1.1 302 ", 13) == 0 ||
        memcmp(pktdata, "HTTP/1.0 302 ", 13) == 0 ||
        memcmp(pktdata, "HTTP/1.1 307 ", 13) == 0) {
        return fast_memmem(pktdata, pktlen, "\r\nLocation:", 11) != NULL;
    }
    return 0;
}

static int find_header_and_get_info(const char *pktdata, unsigned int pktlen,
                                    const char *hdrname,
                                    char **hdrnameaddr,
                                    char **hdrvalueaddr, unsigned int *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;

    *hdrvaluelen = 0u;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;

    hdr_begin = fast_memmem(pktdata, pktlen, hdrname, strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if (pktdata > hdr_begin) return FALSE;

    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = hdr_begin + strlen(hdrname);

    data_addr_rn = fast_memmem(*hdrvalueaddr,
                               pktlen - (uintptr_t)(*hdrvalueaddr - pktdata),
                               "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (unsigned int)(data_addr_rn - *hdrvalueaddr);
        if (*hdrvaluelen >= 3 && *hdrvaluelen <= HOST_MAXLEN)
            return TRUE;
    }
    return FALSE;
}

static inline void change_window_size(const PWINDIVERT_TCPHDR ppTcpHdr, unsigned int size) {
    if (size >= 1 && size <= 0xFFFFu) {
        uint16_t old_win = ppTcpHdr->Window;
        uint16_t new_win = htons((uint16_t)size);
        if (old_win != new_win) {
            ppTcpHdr->Window = new_win;
            ppTcpHdr->Checksum = checksum_update_uint16(ppTcpHdr->Checksum, old_win, new_win);
        }
    }
}

static PVOID find_http_method_end(const char *pkt, unsigned int http_frag, int *is_fragmented) {
    for (size_t i = 0; i < sizeof(http_methods) / sizeof(*http_methods); i++) {
        size_t mlen = strlen(http_methods[i]);
        if (memcmp(pkt, http_methods[i], mlen) == 0) {
            if (is_fragmented) *is_fragmented = 0;
            return (char *)(uintptr_t)pkt + mlen - 1;
        }
        if ((http_frag == 1 || http_frag == 2) &&
            memcmp(pkt, http_methods[i] + http_frag, mlen - http_frag) == 0) {
            if (is_fragmented) *is_fragmented = 1;
            return (char *)(uintptr_t)pkt + mlen - http_frag - 1;
        }
    }
    return NULL;
}

/* ============================================================================
 * 2. Batched WinDivert TX Queue & Core Packet Processing Engine
 * ============================================================================ */
static inline void flush_tx_batch(HANDLE w_filter, char *tx_buf, UINT *tx_len,
                                  WINDIVERT_ADDRESS *tx_addrs, UINT *tx_count) {
    if (*tx_count == 0) return;
    if (*tx_count == 1) {
        WinDivertSend(w_filter, tx_buf, *tx_len, NULL, &tx_addrs[0]);
    } else {
        WinDivertSendEx(w_filter, tx_buf, *tx_len, NULL, 0,
                        tx_addrs, (*tx_count) * (UINT)sizeof(WINDIVERT_ADDRESS), NULL);
    }
    *tx_len = 0;
    *tx_count = 0;
}

static inline void queue_tx_packet(HANDLE w_filter, char *tx_buf, UINT *tx_len,
                                   WINDIVERT_ADDRESS *tx_addrs, UINT *tx_count,
                                   const char *pkt, UINT pkt_len, const WINDIVERT_ADDRESS *paddr) {
    if (*tx_count >= PACKET_BATCH_MAX || *tx_len + pkt_len > PACKET_BATCH_BUF_SIZE) {
        flush_tx_batch(w_filter, tx_buf, tx_len, tx_addrs, tx_count);
    }
    if (UNLIKELY(*tx_count == 0 && pkt_len > PACKET_BATCH_BUF_SIZE)) {
        WinDivertSend(w_filter, pkt, pkt_len, NULL, paddr);
        return;
    }
    memcpy(tx_buf + *tx_len, pkt, pkt_len);
    tx_addrs[*tx_count] = *paddr;
    *tx_len += pkt_len;
    (*tx_count)++;
}

static HANDLE open_divert_handle(const char *filter, UINT64 flags) {
    HANDLE h = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
    if (h != INVALID_HANDLE_VALUE) {
        if (!(flags & WINDIVERT_FLAG_DROP)) {
            WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
            WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_SIZE, 4194304);
            WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 2048);
        }
        return h;
    }
    DWORD err = GetLastError();
    printf("[!] WinDivert baslatilamadi (Hata kodu: %lu).\n", (unsigned long)err);
    if (err == 5) {
        printf("    Lutfen programi Yonetici Olarak (Run as Administrator) calistirin.\n");
    } else if (err == 2) {
        printf("    WinDivert64.sys veya WinDivert32.sys surucu dosyasi bulunamadi.\n");
    }
    return INVALID_HANDLE_VALUE;
}

static DWORD WINAPI engine_worker_thread(PVOID arg) {
    (void)arg;
    static ALIGN64 char batch_buf[PACKET_BATCH_BUF_SIZE];
    static ALIGN64 char tx_batch_buf[PACKET_BATCH_BUF_SIZE];
    static WINDIVERT_ADDRESS addr_batch[PACKET_BATCH_MAX];
    static WINDIVERT_ADDRESS tx_addr_batch[PACKET_BATCH_MAX];
    ALIGN64 char aligned_pkt[MAX_PACKET_SIZE];

#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
#endif

    while (!g_exiting && g_w_filter != INVALID_HANDLE_VALUE) {
        UINT batch_recv_len = 0;
        UINT addr_len_bytes = sizeof(addr_batch);

        if (!WinDivertRecvEx(g_w_filter, batch_buf, sizeof(batch_buf), &batch_recv_len, 0,
                             addr_batch, &addr_len_bytes, NULL)) {
            if (g_exiting) break;
            continue;
        }

        UINT batch_count = addr_len_bytes / (UINT)sizeof(WINDIVERT_ADDRESS);
        if (UNLIKELY(batch_count == 0)) continue;

        const dpi_profile_t *prof = (const dpi_profile_t *)g_active_profile;
        char *cur_pkt = batch_buf;
        UINT rem_len = batch_recv_len;
        UINT tx_batch_len = 0;
        UINT tx_batch_count = 0;

        for (UINT batch_idx = 0; batch_idx < batch_count && rem_len > 0; batch_idx++) {
            UINT cur_len = rem_len;
            if (batch_count > 1 && rem_len >= 20) {
                uint8_t ver = (uint8_t)cur_pkt[0] >> 4;
                if (ver == 4) {
                    uint16_t len4;
                    memcpy(&len4, cur_pkt + 2, 2);
                    UINT total = ntohs(len4);
                    if (total >= 20 && total <= rem_len) cur_len = total;
                } else if (ver == 6 && rem_len >= 40) {
                    uint16_t len6;
                    memcpy(&len6, cur_pkt + 4, 2);
                    UINT total = 40u + (UINT)ntohs(len6);
                    if (total <= rem_len) cur_len = total;
                }
            }

            WINDIVERT_ADDRESS addr = addr_batch[batch_idx];
            UINT packetLen = cur_len <= MAX_PACKET_SIZE ? cur_len : MAX_PACKET_SIZE;
            char *packet;
            if (batch_idx == 0) {
                packet = cur_pkt;
            } else {
                memcpy(aligned_pkt, cur_pkt, packetLen);
                packet = aligned_pkt;
            }
            cur_pkt += cur_len;
            rem_len -= cur_len;

            PWINDIVERT_IPHDR   ppIpHdr   = NULL;
            PWINDIVERT_IPV6HDR ppIpV6Hdr = NULL;
            PWINDIVERT_TCPHDR  ppTcpHdr  = NULL;
            PWINDIVERT_UDPHDR  ppUdpHdr  = NULL;
            PVOID              packet_data = NULL;
            UINT               packet_dataLen = 0;

            if (!WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr, &ppIpV6Hdr,
                                            NULL, NULL, NULL, &ppTcpHdr, &ppUdpHdr,
                                            &packet_data, &packet_dataLen, NULL, NULL)) {
                continue;
            }

            int packet_v4 = (ppIpHdr != NULL);
            int packet_v6 = (ppIpV6Hdr != NULL);
            int should_reinject = 1;
            int should_recalc_checksum = 0;

            /* ------------------------------------------------------------
             * A. UDP Packet Path (QUIC Block, Dual-Stack DNS, Discord Voice)
             * ------------------------------------------------------------ */
            if (ppUdpHdr && packet_dataLen > 0) {
                if (addr.Outbound) {
                    /* 1. Block QUIC (UDP 443) so browsers/Discord use TCP TLS 1.3 */
                    if (prof->do_block_quic && ppUdpHdr->DstPort == htons(443)) {
                        should_reinject = 0;
                    }
                    /* 2. Outbound DNS (UDP 53) Redirection & IPv6 Router DNS Leak Shield */
                    else if (ppUdpHdr->DstPort == htons(53)) {
                        if (packet_v4 && prof->do_dnsv4_redirect) {
                            if (dns_handle_outgoing(&ppIpHdr->SrcAddr, ppUdpHdr->SrcPort,
                                                    &ppIpHdr->DstAddr, ppUdpHdr->DstPort,
                                                    packet_data, packet_dataLen, 0)) {
                                uint32_t old_dip = ppIpHdr->DstAddr;
                                uint16_t old_dport = ppUdpHdr->DstPort;
                                ppIpHdr->DstAddr = prof->dnsv4_addr;
                                ppUdpHdr->DstPort = prof->dnsv4_port;
                                if (addr.IPChecksum && addr.UDPChecksum && ppUdpHdr->Checksum) {
                                    ppIpHdr->Checksum = checksum_update_uint32(ppIpHdr->Checksum, old_dip, prof->dnsv4_addr);
                                    uint16_t ucheck = checksum_update_uint32(ppUdpHdr->Checksum, old_dip, prof->dnsv4_addr);
                                    ucheck = checksum_update_uint16(ucheck, old_dport, prof->dnsv4_port);
                                    ppUdpHdr->Checksum = udp_checksum_fix_zero(ucheck);
                                } else {
                                    should_recalc_checksum = 1;
                                }
                            }
                        } else if (packet_v6 && (prof->do_dnsv4_redirect || prof->do_dnsv6_redirect)) {
                            /* Check if destination is Link-Local Router IPv6 DNS (fe80::/10) */
                            uint32_t first_word = ntohl(ppIpV6Hdr->DstAddr[0]);
                            if ((first_word & 0xFFC00000u) == 0xFE800000u && prof->do_dnsv4_redirect) {
                                /* Drop router link-local IPv6 DNS leak so Windows falls back to IPv4 UDP 53 in <1ms */
                                should_reinject = 0;
                            } else if (prof->do_dnsv6_redirect) {
                                if (dns_handle_outgoing(ppIpV6Hdr->SrcAddr, ppUdpHdr->SrcPort,
                                                        ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
                                                        packet_data, packet_dataLen, 1)) {
                                    memcpy(ppIpV6Hdr->DstAddr, prof->dnsv6_addr, 16);
                                    ppUdpHdr->DstPort = prof->dnsv6_port;
                                    should_recalc_checksum = 1;
                                }
                            }
                        }
                    }
                    /* 3. Discord Voice / WebRTC UDP Desync (STUN / IP Discovery / DTLS) */
                    else if (prof->do_udp_fake &&
                             desync_is_discord_or_webrtc_udp(ppUdpHdr->SrcPort, ppUdpHdr->DstPort,
                                                             (const unsigned char *)packet_data, packet_dataLen)) {
                        flush_tx_batch(g_w_filter, tx_batch_buf, &tx_batch_len, tx_addr_batch, &tx_batch_count);
                        desync_send_udp_fake(g_w_filter, &addr, packet, packetLen, packet_v6);
                    }
                } else {
                    /* Inbound DNS Response Restoration */
                    conntrack_info_t dns_conn;
                    if (packet_v4 && prof->do_dnsv4_redirect &&
                        ppUdpHdr->SrcPort == prof->dnsv4_port && ppIpHdr->SrcAddr == prof->dnsv4_addr) {
                        if (dns_handle_incoming(&ppIpHdr->SrcAddr, ppUdpHdr->SrcPort,
                                                &ppIpHdr->DstAddr, ppUdpHdr->DstPort,
                                                packet_data, packet_dataLen, &dns_conn, 0)) {
                            uint32_t old_sip = ppIpHdr->SrcAddr;
                            uint16_t old_sport = ppUdpHdr->SrcPort;
                            ppIpHdr->SrcAddr = dns_conn.dstip[0];
                            ppUdpHdr->SrcPort = dns_conn.dstport;
                            if (addr.IPChecksum && addr.UDPChecksum && ppUdpHdr->Checksum) {
                                ppIpHdr->Checksum = checksum_update_uint32(ppIpHdr->Checksum, old_sip, dns_conn.dstip[0]);
                                uint16_t ucheck = checksum_update_uint32(ppUdpHdr->Checksum, old_sip, dns_conn.dstip[0]);
                                ucheck = checksum_update_uint16(ucheck, old_sport, dns_conn.dstport);
                                ppUdpHdr->Checksum = udp_checksum_fix_zero(ucheck);
                            } else {
                                should_recalc_checksum = 1;
                            }
                        }
                    } else if (packet_v6 && prof->do_dnsv6_redirect &&
                               ppUdpHdr->SrcPort == prof->dnsv6_port &&
                               memcmp(ppIpV6Hdr->SrcAddr, prof->dnsv6_addr, 16) == 0) {
                        if (dns_handle_incoming(ppIpV6Hdr->SrcAddr, ppUdpHdr->SrcPort,
                                                ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
                                                packet_data, packet_dataLen, &dns_conn, 1)) {
                            memcpy(ppIpV6Hdr->SrcAddr, dns_conn.dstip, 16);
                            ppUdpHdr->SrcPort = dns_conn.dstport;
                            should_recalc_checksum = 1;
                        }
                    }
                }
            }
            /* ------------------------------------------------------------
             * B. TCP Packet with Data Path (TLS ClientHello & HTTP Desync)
             * ------------------------------------------------------------ */
            else if (ppTcpHdr && packet_dataLen > 0) {
                if (!addr.Outbound) {
                    /* Inbound Passive DPI HTTP 302/307 Block-Page Drop */
                    if (prof->do_passivedpi && is_passivedpi_redirect(packet_data, packet_dataLen)) {
                        should_reinject = 0;
                    }
                } else if (!prof->max_payload_size ||
                           packet_dataLen <= prof->max_payload_size ||
                           (packet_dataLen >= 6 &&
                            ((const unsigned char *)packet_data)[0] == 0x16 &&
                            ((const unsigned char *)packet_data)[1] == 0x03)) {

                    sni_info_t sni = { NULL, 0, 0 };
                    int is_tls_ch = (packet_dataLen >= 44 &&
                                     (ppTcpHdr->DstPort == htons(443) || prof->do_http_allports) &&
                                     extract_sni_info(packet_data, packet_dataLen, &sni));

                    if (is_tls_ch) {
                        if (!prof->do_blacklist || blackwhitelist_check_hostname(sni.host_ptr, sni.host_len)) {
                            flush_tx_batch(g_w_filter, tx_batch_buf, &tx_batch_len, tx_addr_batch, &tx_batch_count);

                            /* 1. Inject Multi-Fooling Decoy ClientHello if enabled */
                            if (prof->do_fake_packet) {
                                uint8_t eff_ttl = prof->fake_ttl;
                                if ((prof->fooling_flags & FOOL_AUTOTTL) || prof->min_nhops) {
                                    tcp_conntrack_info_t tconn;
                                    if (tcp_handle_outgoing(packet_v4 ? &ppIpHdr->SrcAddr : ppIpV6Hdr->SrcAddr,
                                                            ppTcpHdr->SrcPort,
                                                            packet_v4 ? &ppIpHdr->DstAddr : ppIpV6Hdr->DstAddr,
                                                            ppTcpHdr->DstPort, &tconn, (uint8_t)packet_v6)) {
                                        if (prof->fooling_flags & FOOL_AUTOTTL) {
                                            eff_ttl = tcp_get_auto_ttl(tconn.ttl, prof->auto_ttl_delta,
                                                                       prof->auto_ttl_min, prof->min_nhops,
                                                                       prof->auto_ttl_max);
                                        }
                                    }
                                }
                                desync_send_fake_tcp(g_w_filter, &addr, packet, packetLen,
                                                     packet_v6, eff_ttl, prof->fooling_flags, 1);
                            }

                            /* 2. Split TLS ClientHello (2-way or 3-way SNI-Midpoint Disorder) */
                            if (prof->do_fragment_https) {
                                unsigned int pos1 = prof->https_frag_size ? prof->https_frag_size : 2u;
                                unsigned int pos2 = 0u;

                                if (prof->do_split_sni && sni.host_offset > pos1 && sni.host_len >= 4) {
                                    /* Split right across the middle of the SNI domain (e.g. "dis" | "cord.com") */
                                    pos2 = (unsigned int)sni.host_offset + ((unsigned int)sni.host_len / 2u);
                                } else if (prof->do_fragment_by_sni && sni.host_offset > 0) {
                                    pos1 = (unsigned int)sni.host_offset;
                                }

                                if (prof->do_native_frag) {
                                    if (desync_send_tcp_split(g_w_filter, &addr, packet, packetLen,
                                                              packet_data, packet_dataLen,
                                                              packet_v4, packet_v6,
                                                              ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                                              pos1, pos2, prof->do_reverse_frag) == 0) {
                                        should_reinject = 0;
                                    }
                                } else {
                                    change_window_size(ppTcpHdr, pos1);
                                }
                            }
                        }
                    } else if (packet_dataLen >= 16) {
                        /* Outbound HTTP Plaintext Desync */
                        int http_req_fragmented = 0;
                        PVOID method_addr = find_http_method_end(packet_data,
                                                                 prof->do_fragment_http ? prof->http_frag_size : 0u,
                                                                 &http_req_fragmented);
                        if (method_addr) {
                            char *host_addr = NULL, *hdr_name_addr = NULL, *hdr_value_addr = NULL;
                            unsigned int host_len = 0, hdr_value_len = 0;

                            if (find_header_and_get_info(method_addr,
                                                         packet_dataLen - (unsigned int)((const char *)method_addr - (const char *)packet_data),
                                                         "\r\nHost: ", &hdr_name_addr, &host_addr, &host_len) &&
                                (!prof->do_blacklist || blackwhitelist_check_hostname(host_addr, host_len))) {

                                flush_tx_batch(g_w_filter, tx_batch_buf, &tx_batch_len, tx_addr_batch, &tx_batch_count);

                                if (prof->do_fake_packet) {
                                    uint8_t eff_ttl = prof->fake_ttl;
                                    if ((prof->fooling_flags & FOOL_AUTOTTL) || prof->min_nhops) {
                                        tcp_conntrack_info_t tconn;
                                        if (tcp_handle_outgoing(packet_v4 ? &ppIpHdr->SrcAddr : ppIpV6Hdr->SrcAddr,
                                                                ppTcpHdr->SrcPort,
                                                                packet_v4 ? &ppIpHdr->DstAddr : ppIpV6Hdr->DstAddr,
                                                                ppTcpHdr->DstPort, &tconn, (uint8_t)packet_v6)) {
                                            if (prof->fooling_flags & FOOL_AUTOTTL) {
                                                eff_ttl = tcp_get_auto_ttl(tconn.ttl, prof->auto_ttl_delta,
                                                                           prof->auto_ttl_min, prof->min_nhops,
                                                                           prof->auto_ttl_max);
                                            }
                                        }
                                    }
                                    desync_send_fake_tcp(g_w_filter, &addr, packet, packetLen,
                                                         packet_v6, eff_ttl, prof->fooling_flags, 0);
                                }

                                if (prof->do_host_mixedcase) {
                                    mix_case(host_addr, host_len);
                                    should_recalc_checksum = 1;
                                }
                                if (prof->do_host) {
                                    memcpy(hdr_name_addr + 2, "hoSt", 4);
                                    should_recalc_checksum = 1;
                                }
                                if (prof->do_additional_space && prof->do_host_removespace) {
                                    char *ua_end = fast_memmem(method_addr,
                                                               packet_dataLen - (unsigned int)((const char *)method_addr - (const char *)packet_data),
                                                               "\r\n", 2);
                                    if (ua_end && ua_end > host_addr) {
                                        memmove(host_addr - 1, host_addr, (size_t)(ua_end - host_addr));
                                        *(ua_end - 1) = ' ';
                                        should_recalc_checksum = 1;
                                    }
                                } else if (prof->do_host_removespace) {
                                    if (find_header_and_get_info(method_addr,
                                                                 packet_dataLen - (unsigned int)((const char *)method_addr - (const char *)packet_data),
                                                                 "\r\nUser-Agent: ", &hdr_name_addr, &hdr_value_addr, &hdr_value_len)) {
                                        if (hdr_value_addr > host_addr) {
                                            memmove(host_addr - 1, host_addr, (size_t)(hdr_value_addr - host_addr + hdr_value_len));
                                            *(hdr_value_addr + hdr_value_len - 1) = ' ';
                                        } else {
                                            memmove(hdr_value_addr + hdr_value_len + 1,
                                                    hdr_value_addr + hdr_value_len,
                                                    (size_t)(host_addr - 1 - (hdr_value_addr + hdr_value_len)));
                                            *(hdr_value_addr + hdr_value_len) = ' ';
                                        }
                                        should_recalc_checksum = 1;
                                    }
                                }

                                if (prof->do_fragment_http && !http_req_fragmented) {
                                    if (prof->do_native_frag) {
                                        if (desync_send_tcp_split(g_w_filter, &addr, packet, packetLen,
                                                                  packet_data, packet_dataLen,
                                                                  packet_v4, packet_v6,
                                                                  ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                                                  prof->http_frag_size, 0,
                                                                  prof->do_reverse_frag) == 0) {
                                            should_reinject = 0;
                                        }
                                    } else {
                                        change_window_size(ppTcpHdr, prof->http_frag_size);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            /* ------------------------------------------------------------
             * C. Pure TCP Control Packet Path (SYN-ACK Auto-TTL & Window)
             * ------------------------------------------------------------ */
            else if (ppTcpHdr && packet_dataLen == 0) {
                if (!addr.Outbound && ppTcpHdr->Syn == 1 && ppTcpHdr->Ack == 1) {
                    if ((prof->fooling_flags & FOOL_AUTOTTL) || prof->min_nhops) {
                        tcp_handle_incoming(packet_v4 ? &ppIpHdr->SrcAddr : ppIpV6Hdr->SrcAddr,
                                            ppTcpHdr->SrcPort,
                                            packet_v4 ? &ppIpHdr->DstAddr : ppIpV6Hdr->DstAddr,
                                            ppTcpHdr->DstPort,
                                            (uint8_t)packet_v6,
                                            packet_v4 ? ppIpHdr->TTL : ppIpV6Hdr->HopLimit);
                    }
                    if (prof->do_fragment_http && !prof->do_native_frag && ppTcpHdr->SrcPort == htons(80)) {
                        change_window_size(ppTcpHdr, prof->http_frag_size);
                    } else if (prof->do_fragment_https && !prof->do_native_frag && ppTcpHdr->SrcPort != htons(80)) {
                        change_window_size(ppTcpHdr, prof->https_frag_size);
                    }
                }
            }

            if (should_reinject) {
                if (should_recalc_checksum) {
                    WinDivertHelperCalcChecksums(packet, packetLen, &addr, (UINT64)0LL);
                }
                if (batch_count == 1) {
                    WinDivertSend(g_w_filter, packet, packetLen, NULL, &addr);
                } else {
                    queue_tx_packet(g_w_filter, tx_batch_buf, &tx_batch_len,
                                    tx_addr_batch, &tx_batch_count, packet, packetLen, &addr);
                }
            }
        }
        flush_tx_batch(g_w_filter, tx_batch_buf, &tx_batch_len, tx_addr_batch, &tx_batch_count);
    }
    return 0;
}

/* ============================================================================
 * 3. Lifecycle, Signal Handling, UAC Elevation & Native Service Manager
 * ============================================================================ */
void deinit_all(void) {
    g_exiting = 1;
    if (g_w_filter != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(g_w_filter, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(g_w_filter);
        g_w_filter = INVALID_HANDLE_VALUE;
    }
    if (g_quic_filter != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(g_quic_filter, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(g_quic_filter);
        g_quic_filter = INVALID_HANDLE_VALUE;
    }
    desync_cleanup();
}

static void sigint_handler(int sig) {
    (void)sig;
    deinit_all();
    exit(EXIT_SUCCESS);
}

#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)

#define WM_TRAYICON             (WM_APP + 1)
#define WM_TRAY_ALREADY_RUNNING (WM_APP + 2)
#define TRAY_ICON_ID            1

#define ID_TRAY_PROFILE_BASE    1000
#define ID_TRAY_AUTO            1010
#define ID_TRAY_TEST            1011
#define ID_TRAY_TOGGLE          1012
#define ID_TRAY_AUTOSTART       1013
#define ID_TRAY_CLEANUP         1014
#define ID_TRAY_EXIT            1015

#define CONFIG_FILE_NAME        "turkdpi.cfg"
#define AUTOSTART_TASK_NAME     "TurkDPI_Autostart"

static HANDLE          g_worker_thread = NULL;
static HWND            g_tray_hwnd     = NULL;
static NOTIFYICONDATAW g_nid;
static volatile int    g_current_profile_idx = 0;
static volatile int    g_probing             = 0;
static int             g_autostart_enabled   = 0;

static const wchar_t *g_profile_labels_w[TURKDPI_NUM_PROFILES] = {
    L"[0] Standart Türkiye (TT / TurkNet / Kablonet)",
    L"[1] Superonline & Vodafone Modern (MD5Sig + Auto-TTL)",
    L"[2] Superonline Alternatif 1 (Auto-TTL + BadSeq)",
    L"[3] Superonline Alternatif 2 (Sabit TTL 4 + BadSeq)",
    L"[4] Superonline Alternatif 3 (Klasik TTL 3)",
    L"[5] ByeDPI Saf SNI-Disorder (Oyun Modu - Sahte Paketsiz)",
    L"[6] Cloudflare DNS (1.1.1.1) + Hibrit (Yurt / Kampüs)"
};

static int is_process_elevated(void) {
    BOOL is_elevated = FALSE;
    HANDLE h_token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token)) {
        TOKEN_ELEVATION elev;
        DWORD cb_size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(h_token, TokenElevation, &elev, sizeof(elev), &cb_size)) {
            is_elevated = (BOOL)elev.TokenIsElevated;
        }
        CloseHandle(h_token);
    }
    return is_elevated;
}

static void chdir_to_exe_dir(void) {
    char exe_dir[MAX_PATH];
    if (GetModuleFileNameA(NULL, exe_dir, MAX_PATH)) {
        char *last_slash = strrchr(exe_dir, '\\');
        if (last_slash) {
            *last_slash = '\0';
            SetCurrentDirectoryA(exe_dir);
        }
    }
}

static void ensure_admin_privileges(int argc, char *argv[]) {
    if (is_process_elevated()) return;

    char exe_path[MAX_PATH];
    char exe_dir[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exe_path, MAX_PATH)) return;
    memcpy(exe_dir, exe_path, sizeof(exe_dir));
    char *last_slash = strrchr(exe_dir, '\\');
    if (last_slash) *last_slash = '\0';

    char params[2048] = {0};
    for (int i = 1; i < argc; i++) {
        size_t cur = strlen(params);
        snprintf(params + cur, sizeof(params) - cur, "%s\"%s\"", (i > 1 ? " " : ""), argv[i]);
    }

    SHELLEXECUTEINFOA sei;
    memset(&sei, 0, sizeof(sei));
    sei.cbSize       = sizeof(sei);
    sei.lpVerb       = "runas";
    sei.lpFile       = exe_path;
    sei.lpParameters = params[0] ? params : NULL;
    sei.lpDirectory  = exe_dir;
    sei.nShow        = SW_HIDE;

    if (ShellExecuteExA(&sei)) {
        exit(EXIT_SUCCESS);
    }
}

static int run_hidden_cmd(const char *cmdline) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", cmdline);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)exit_code;
}

static int check_autostart_task(void) {
    return run_hidden_cmd("schtasks /query /tn \"" AUTOSTART_TASK_NAME "\"") == 0;
}

static int set_autostart_task(int enable) {
    if (!enable) {
        run_hidden_cmd("schtasks /delete /tn \"" AUTOSTART_TASK_NAME "\" /f");
        g_autostart_enabled = 0;
        return 0;
    }
    char exe_path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exe_path, MAX_PATH)) return -1;
    char cmd[MAX_PATH + 256];
    snprintf(cmd, sizeof(cmd),
             "schtasks /create /tn \"" AUTOSTART_TASK_NAME "\" /tr \"\\\"%s\\\"\" /sc onlogon /rl highest /f",
             exe_path);
    if (run_hidden_cmd(cmd) == 0) {
        g_autostart_enabled = 1;
        return 0;
    }
    return -1;
}

static int scm_remove_service(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        const char *svc_names[] = { SERVICE_NAME, "WinDivert", "WinDivert14" };
        for (size_t i = 0; i < 3; i++) {
            SC_HANDLE svc = OpenServiceA(scm, svc_names[i], SERVICE_STOP | DELETE);
            if (svc) {
                SERVICE_STATUS st;
                ControlService(svc, SERVICE_CONTROL_STOP, &st);
                DeleteService(svc);
                CloseServiceHandle(svc);
            }
        }
        CloseServiceHandle(scm);
    }
    set_autostart_task(0);
    DeleteFileA(CONFIG_FILE_NAME);
    flush_dns_cache();
    return 0;
}

static void stop_conflicting_windows_service(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_STOP | DELETE);
        if (svc) {
            SERVICE_STATUS st;
            ControlService(svc, SERVICE_CONTROL_STOP, &st);
            DeleteService(svc);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
}

static int load_saved_profile(int *has_saved) {
    *has_saved = 0;
    FILE *fp = fopen(CONFIG_FILE_NAME, "r");
    if (!fp) return 0;
    int idx = 0;
    if (fscanf(fp, "%d", &idx) == 1 && idx >= 0 && idx < TURKDPI_NUM_PROFILES) {
        *has_saved = 1;
        fclose(fp);
        return idx;
    }
    fclose(fp);
    return 0;
}

static void save_selected_profile(int idx) {
    FILE *fp = fopen(CONFIG_FILE_NAME, "w");
    if (fp) {
        fprintf(fp, "%d\n", idx);
        fclose(fp);
    }
}

/* ============================================================================
 * 4. Native Win32 System Tray Engine & Right-Click Menu
 * ============================================================================ */
static void tray_show_balloon(const wchar_t *title, const wchar_t *msg, DWORD info_flags) {
    if (!g_tray_hwnd) return;
    g_nid.uFlags      = NIF_INFO | NIF_TIP;
    g_nid.dwInfoFlags = info_flags;
    wcsncpy(g_nid.szInfoTitle, title, 63);
    g_nid.szInfoTitle[63] = L'\0';
    wcsncpy(g_nid.szInfo, msg, 255);
    g_nid.szInfo[255] = L'\0';
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void tray_update_tooltip(void) {
    if (!g_tray_hwnd) return;
    g_nid.uFlags = NIF_TIP;
    if (g_probing) {
        swprintf(g_nid.szTip, 127, L"TurkDPI v2.0 — İSS Analiz Ediliyor...");
    } else if (g_w_filter != INVALID_HANDLE_VALUE) {
        swprintf(g_nid.szTip, 127, L"TurkDPI v2.0 — Aktif [Profil %d]", g_current_profile_idx);
    } else {
        swprintf(g_nid.szTip, 127, L"TurkDPI v2.0 — Duraklatıldı");
    }
    g_nid.szTip[127] = L'\0';
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static int start_engine_bg(void) {
    if (g_w_filter != INVALID_HANDLE_VALUE) return 1;
    g_exiting = 0;
    g_w_filter = open_divert_handle(TURKDPI_MAIN_FILTER, 0);
    if (g_w_filter == INVALID_HANDLE_VALUE) {
        tray_update_tooltip();
        return 0;
    }
    flush_dns_cache();
    g_worker_thread = CreateThread(NULL, 0, engine_worker_thread, NULL, 0, NULL);
    tray_update_tooltip();
    return 1;
}

static void stop_engine_bg(void) {
    g_exiting = 1;
    if (g_w_filter != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(g_w_filter, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(g_w_filter);
        g_w_filter = INVALID_HANDLE_VALUE;
    }
    if (g_worker_thread) {
        WaitForSingleObject(g_worker_thread, 1500);
        CloseHandle(g_worker_thread);
        g_worker_thread = NULL;
    }
    tray_update_tooltip();
}

static DWORD WINAPI tray_autoprobe_thread(PVOID arg) {
    (void)arg;
    if (g_probing) return 0;
    g_probing = 1;
    start_engine_bg();
    tray_update_tooltip();

    int best = probe_find_best_profile(&g_active_profile);
    g_current_profile_idx = best;
    g_active_profile = &g_turkdpi_profiles[best];
    save_selected_profile(best);
    flush_dns_cache();

    g_probing = 0;
    tray_update_tooltip();

    wchar_t msg[256];
    swprintf(msg, 255, L"%ls aktif edildi.\nDiscord (Web + Ses) ve tüm engelli uygulamalar açık!",
             g_profile_labels_w[best]);
    tray_show_balloon(L"TurkDPI — En Uygun Profil Bulundu", msg, NIIF_INFO);
    return 0;
}

static DWORD WINAPI tray_test_thread(PVOID arg) {
    (void)arg;
    uint32_t dip = probe_resolve_domain("discord.com", 0xE8879FA2u);
    int ms = probe_test_https_target(dip, 443, "discord.com", 2000);
    wchar_t msg[256];
    if (ms > 0) {
        swprintf(msg, 255, L"Discord TLS 1.3 Erişimi: AÇIK (%d ms)\nAktif: %ls",
                 ms, g_profile_labels_w[g_current_profile_idx]);
        tray_show_balloon(L"TurkDPI — Bağlantı Testi Başarılı", msg, NIIF_INFO);
    } else {
        swprintf(msg, 255, L"Discord TLS 1.3 yanıtı alınamadı.\nMenüden 'Otomatik İSS Algıla' seçeneğine tıklayın.");
        tray_show_balloon(L"TurkDPI — Bağlantı Uyarısı", msg, NIIF_WARNING);
    }
    return 0;
}

static void show_tray_context_menu(HWND hwnd) {
    HMENU h_menu = CreatePopupMenu();
    if (!h_menu) return;

    wchar_t status_line[128];
    if (g_probing) {
        swprintf(status_line, 127, L"⏳ TurkDPI v2.0 — İSS Profili Taranıyor...");
    } else if (g_w_filter != INVALID_HANDLE_VALUE) {
        swprintf(status_line, 127, L"● TurkDPI v2.0 — Aktif [Profil %d]", g_current_profile_idx);
    } else {
        swprintf(status_line, 127, L"○ TurkDPI v2.0 — Duraklatıldı");
    }
    AppendMenuW(h_menu, MF_STRING | MF_DISABLED | MF_GRAYED, 0, status_line);
    AppendMenuW(h_menu, MF_SEPARATOR, 0, NULL);

    AppendMenuW(h_menu, MF_STRING | (g_probing ? MF_GRAYED : 0),
                ID_TRAY_AUTO, L"⚡ Otomatik İSS Algıla (En Hızlı Profili Bul)");
    AppendMenuW(h_menu, MF_STRING,
                ID_TRAY_TEST, L"🔍 Discord & TLS 1.3 Bağlantısını Test Et");
    AppendMenuW(h_menu, MF_SEPARATOR, 0, NULL);

    for (int i = 0; i < TURKDPI_NUM_PROFILES; i++) {
        UINT flags = MF_STRING;
        if (i == g_current_profile_idx && g_w_filter != INVALID_HANDLE_VALUE) {
            flags |= MF_CHECKED;
        }
        AppendMenuW(h_menu, flags, ID_TRAY_PROFILE_BASE + i, g_profile_labels_w[i]);
    }

    AppendMenuW(h_menu, MF_SEPARATOR, 0, NULL);
    if (g_w_filter != INVALID_HANDLE_VALUE) {
        AppendMenuW(h_menu, MF_STRING, ID_TRAY_TOGGLE, L"⏸ DPI Filtresini Duraklat");
    } else {
        AppendMenuW(h_menu, MF_STRING, ID_TRAY_TOGGLE, L"▶ DPI Filtresini Başlat");
    }

    AppendMenuW(h_menu, MF_STRING | (g_autostart_enabled ? MF_CHECKED : 0),
                ID_TRAY_AUTOSTART, L"🚀 Windows Açılışında Otomatik Başlat");
    AppendMenuW(h_menu, MF_STRING,
                ID_TRAY_CLEANUP, L"🧹 Sürücü ve Ayarları Sıfırla (Tamamen Kaldır)");
    AppendMenuW(h_menu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(h_menu, MF_STRING, ID_TRAY_EXIT, L"❌ Çıkış");

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(h_menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, NULL);
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(h_menu);
}

static LRESULT CALLBACK tray_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    static UINT s_wm_taskbar_restart = 0;

    switch (msg) {
        case WM_CREATE:
            s_wm_taskbar_restart = RegisterWindowMessageW(L"TaskbarCreated");
            return 0;

        case WM_TRAYICON:
            if (lparam == WM_RBUTTONUP || lparam == WM_LBUTTONUP || lparam == WM_CONTEXTMENU) {
                show_tray_context_menu(hwnd);
            }
            return 0;

        case WM_TRAY_ALREADY_RUNNING:
            tray_show_balloon(L"TurkDPI Zaten Çalışıyor",
                              L"Sağ alt köşedeki (System Tray) TurkDPI simgesine sağ tıklayarak ayarları değiştirebilirsiniz.",
                              NIIF_INFO);
            return 0;

        case WM_COMMAND: {
            UINT cmd = LOWORD(wparam);
            if (cmd >= ID_TRAY_PROFILE_BASE && cmd < ID_TRAY_PROFILE_BASE + TURKDPI_NUM_PROFILES) {
                int idx = (int)(cmd - ID_TRAY_PROFILE_BASE);
                g_current_profile_idx = idx;
                g_active_profile = &g_turkdpi_profiles[idx];
                save_selected_profile(idx);
                if (g_w_filter == INVALID_HANDLE_VALUE) {
                    start_engine_bg();
                } else {
                    flush_dns_cache();
                    tray_update_tooltip();
                }
                tray_show_balloon(L"TurkDPI — Profil Değiştirildi", g_profile_labels_w[idx], NIIF_INFO);
            } else if (cmd == ID_TRAY_AUTO) {
                tray_show_balloon(L"TurkDPI — Otomatik İSS Algılama",
                                  L"İSS'niz için en hızlı çalışan profil test ediliyor, lütfen birkaç saniye bekleyin...",
                                  NIIF_INFO);
                HANDLE ht = CreateThread(NULL, 0, tray_autoprobe_thread, NULL, 0, NULL);
                if (ht) CloseHandle(ht);
            } else if (cmd == ID_TRAY_TEST) {
                HANDLE ht = CreateThread(NULL, 0, tray_test_thread, NULL, 0, NULL);
                if (ht) CloseHandle(ht);
            } else if (cmd == ID_TRAY_TOGGLE) {
                if (g_w_filter != INVALID_HANDLE_VALUE) {
                    stop_engine_bg();
                    tray_show_balloon(L"TurkDPI — Duraklatıldı",
                                      L"DPI filtresi geçici olarak duraklatıldı.",
                                      NIIF_WARNING);
                } else {
                    if (start_engine_bg()) {
                        tray_show_balloon(L"TurkDPI — Aktif",
                                          g_profile_labels_w[g_current_profile_idx],
                                          NIIF_INFO);
                    }
                }
            } else if (cmd == ID_TRAY_AUTOSTART) {
                if (set_autostart_task(!g_autostart_enabled) == 0) {
                    tray_show_balloon(L"TurkDPI — Başlangıç Ayarı",
                                      g_autostart_enabled
                                          ? L"Windows açıldığında sağ alt tepside otomatik başlayacak."
                                          : L"Windows açılışında otomatik başlatma kapatıldı.",
                                      NIIF_INFO);
                }
            } else if (cmd == ID_TRAY_CLEANUP) {
                stop_engine_bg();
                scm_remove_service();
                Shell_NotifyIconW(NIM_DELETE, &g_nid);
                PostQuitMessage(0);
            } else if (cmd == ID_TRAY_EXIT) {
                stop_engine_bg();
                Shell_NotifyIconW(NIM_DELETE, &g_nid);
                PostQuitMessage(0);
            }
            return 0;
        }

        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &g_nid);
            PostQuitMessage(0);
            return 0;

        default:
            if (s_wm_taskbar_restart != 0 && msg == s_wm_taskbar_restart) {
                Shell_NotifyIconW(NIM_ADD, &g_nid);
                return 0;
            }
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

static int run_system_tray_app(int initial_profile, int force_auto) {
    HANDLE h_mutex = CreateMutexW(NULL, TRUE, L"Local\\TurkDPI_Tray_Instance");
    if (h_mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND existing = FindWindowW(L"TurkDPI_Tray_Class", NULL);
        if (existing) {
            PostMessageW(existing, WM_TRAY_ALREADY_RUNNING, 0, 0);
        }
        CloseHandle(h_mutex);
        return 0;
    }

    stop_conflicting_windows_service();
    g_autostart_enabled = check_autostart_task();

    int has_saved = 0;
    if (initial_profile >= 0 && initial_profile < TURKDPI_NUM_PROFILES) {
        g_current_profile_idx = initial_profile;
        has_saved = 1;
    } else {
        g_current_profile_idx = load_saved_profile(&has_saved);
    }
    g_active_profile = &g_turkdpi_profiles[g_current_profile_idx];

    HINSTANCE h_inst = GetModuleHandleW(NULL);
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = tray_wnd_proc;
    wc.hInstance     = h_inst;
    wc.lpszClassName = L"TurkDPI_Tray_Class";
    RegisterClassExW(&wc);

    g_tray_hwnd = CreateWindowExW(0, L"TurkDPI_Tray_Class", L"TurkDPI", 0,
                                  0, 0, 0, 0, NULL, NULL, h_inst, NULL);
    if (!g_tray_hwnd) {
        if (h_mutex) CloseHandle(h_mutex);
        return 1;
    }

    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = g_tray_hwnd;
    g_nid.uID              = TRAY_ICON_ID;
    g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon            = LoadIconW(h_inst, MAKEINTRESOURCEW(1));
    if (!g_nid.hIcon) {
        g_nid.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    }
    swprintf(g_nid.szTip, 127, L"TurkDPI v2.0 — Başlatılıyor...");
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    if (!start_engine_bg()) {
        MessageBoxW(NULL,
                    L"WinDivert sürücüsü başlatılamadı!\nWinDivert.dll ve WinDivert64.sys dosyalarının programla aynı klasörde olduğundan emin olun.",
                    L"TurkDPI Hatası", MB_ICONERROR | MB_OK);
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        if (h_mutex) CloseHandle(h_mutex);
        return 1;
    }

    if (force_auto || !has_saved) {
        /* First run or --auto: automatically probe best ISP profile in background */
        tray_show_balloon(L"TurkDPI — Otomatik İSS Algılama",
                          L"İlk çalıştırma: İSS'niz için en hızlı Discord & DPI profili otomatik taranıyor...",
                          NIIF_INFO);
        HANDLE ht = CreateThread(NULL, 0, tray_autoprobe_thread, NULL, 0, NULL);
        if (ht) CloseHandle(ht);
    } else {
        tray_show_balloon(L"TurkDPI v2.0 — Arka Planda Aktif",
                          g_profile_labels_w[g_current_profile_idx],
                          NIIF_INFO);
    }

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    stop_engine_bg();
    if (h_mutex) CloseHandle(h_mutex);
    return 0;
}

#endif /* _WIN32 */

/* ============================================================================
 * 5. CLI Argument Parser & Entry Point
 * ============================================================================ */
static struct option long_options[] = {
    {"auto",        no_argument,       0, 'A'},
    {"remove",      no_argument,       0, 'R'},
    {"profile",     required_argument, 0, 'P'},
    {"run",         required_argument, 0, 'P'},
    {"split-sni",   no_argument,       0,  1 },
    {"md5sig",      no_argument,       0,  2 },
    {"udp-fake",    no_argument,       0,  3 },
    {"dns-addr",    required_argument, 0, 'd'},
    {"dns-port",    required_argument, 0, 'g'},
    {"dnsv6-addr",  required_argument, 0, '!'},
    {"dnsv6-port",  required_argument, 0, '@'},
    {"dns-verb",    no_argument,       0, 'v'},
    {"blacklist",   required_argument, 0, 'b'},
    {"allow-no-sni",no_argument,       0, ']'},
    {"frag-by-sni", no_argument,       0, '>'},
    {"set-ttl",     required_argument, 0, '$'},
    {"min-ttl",     required_argument, 0, '['},
    {"auto-ttl",    optional_argument, 0, '+'},
    {"wrong-chksum",no_argument,       0, '%'},
    {"wrong-seq",   no_argument,       0, ')'},
    {"native-frag", no_argument,       0, '*'},
    {"reverse-frag",no_argument,       0, '('},
    {"max-payload", optional_argument, 0, '^'},
    {"port",        required_argument, 0, 'z'},
    {"ip-id",       required_argument, 0, 'i'},
    {"fake-from-hex", required_argument, 0, '#'},
    {"fake-gen",    required_argument, 0, '&'},
    {"fake-with-sni", required_argument, 0, '<'},
    {"debug-exit",  no_argument,       0, '|'},
    {0, 0, 0, 0}
};

int main(int argc, char *argv[]) {
#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
    SetDllDirectoryA("");
    SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);
    chdir_to_exe_dir();
#endif

    desync_init_defaults();
    g_custom_profile = g_turkdpi_profiles[0];

    int mode_auto         = 0;
    int mode_remove       = 0;
    int selected_profile  = -1;
    int legacy_flags_used = 0;
    int debug_exit        = 0;

    if (argc > 1) {
        memset(&g_custom_profile, 0, sizeof(g_custom_profile));
        g_custom_profile.name           = "Ozel CLI Yapilandirmasi (Hybrid Desync)";
        g_custom_profile.isp_hint       = "Ozel Parametreler";
        g_custom_profile.do_split_sni   = 1;
        g_custom_profile.do_udp_fake    = 1;
        g_custom_profile.auto_ttl_delta = 1;
        g_custom_profile.auto_ttl_min   = 3;
        g_custom_profile.auto_ttl_max   = 10;
        g_custom_profile.dnsv4_port     = htons(53);
        g_custom_profile.dnsv6_port     = htons(53);
    }

    int opt;
    while ((opt = getopt_long(argc, argv, "123456789pqrsaf:e:mwk:nARP:d:g:v:b:z:i:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'A': mode_auto = 1; break;
            case 'R': mode_remove = 1; break;
            case 'P':
                selected_profile = atoi(optarg);
                if (selected_profile < 0 || selected_profile >= TURKDPI_NUM_PROFILES) selected_profile = 0;
                break;
            case 1: g_custom_profile.do_split_sni = 1; break;
            case 2: g_custom_profile.do_fake_packet = 1; g_custom_profile.fooling_flags |= FOOL_MD5SIG; break;
            case 3: g_custom_profile.do_udp_fake = 1; break;
            case '1':
                legacy_flags_used = 1;
                g_custom_profile.do_passivedpi = g_custom_profile.do_host = g_custom_profile.do_host_removespace = 1;
                g_custom_profile.do_fragment_http = g_custom_profile.do_fragment_https = 1;
                g_custom_profile.do_fragment_http_persistent = g_custom_profile.do_fragment_http_persistent_nowait = 1;
                g_custom_profile.http_frag_size = 2;
                g_custom_profile.https_frag_size = 2;
                break;
            case '2':
                legacy_flags_used = 1;
                g_custom_profile.do_passivedpi = g_custom_profile.do_host = g_custom_profile.do_host_removespace = 1;
                g_custom_profile.do_fragment_http = g_custom_profile.do_fragment_https = 1;
                g_custom_profile.do_fragment_http_persistent = g_custom_profile.do_fragment_http_persistent_nowait = 1;
                g_custom_profile.http_frag_size = 2;
                g_custom_profile.https_frag_size = 40;
                break;
            case '3':
                legacy_flags_used = 1;
                g_custom_profile.do_passivedpi = g_custom_profile.do_host = g_custom_profile.do_host_removespace = 1;
                g_custom_profile.do_fragment_https = 1;
                g_custom_profile.https_frag_size = 40;
                break;
            case '4':
                legacy_flags_used = 1;
                g_custom_profile.do_passivedpi = g_custom_profile.do_host = g_custom_profile.do_host_removespace = 1;
                break;
            case '5':
                legacy_flags_used = 1;
                g_custom_profile.do_fragment_http = g_custom_profile.do_fragment_https = 1;
                g_custom_profile.do_reverse_frag = g_custom_profile.do_native_frag = 1;
                g_custom_profile.http_frag_size = g_custom_profile.https_frag_size = 2;
                g_custom_profile.do_fragment_http_persistent = g_custom_profile.do_fragment_http_persistent_nowait = 1;
                g_custom_profile.do_fake_packet = 1;
                g_custom_profile.fooling_flags |= (FOOL_AUTOTTL | FOOL_MD5SIG | FOOL_BADSEQ);
                g_custom_profile.do_block_quic = 1;
                g_custom_profile.max_payload_size = 1200;
                break;
            case '6':
                legacy_flags_used = 1;
                g_custom_profile.do_fragment_http = g_custom_profile.do_fragment_https = 1;
                g_custom_profile.do_reverse_frag = g_custom_profile.do_native_frag = 1;
                g_custom_profile.http_frag_size = g_custom_profile.https_frag_size = 2;
                g_custom_profile.do_fragment_http_persistent = g_custom_profile.do_fragment_http_persistent_nowait = 1;
                g_custom_profile.do_fake_packet = 1;
                g_custom_profile.fooling_flags |= FOOL_BADSEQ;
                g_custom_profile.max_payload_size = 1200;
                break;
            case '9':
                g_custom_profile.do_block_quic = 1;
                /* fallthrough */
            case '8':
                g_custom_profile.fooling_flags |= FOOL_BADSEQ;
                /* fallthrough */
            case '7':
                legacy_flags_used = 1;
                g_custom_profile.do_fragment_http = g_custom_profile.do_fragment_https = 1;
                g_custom_profile.do_reverse_frag = g_custom_profile.do_native_frag = 1;
                g_custom_profile.http_frag_size = g_custom_profile.https_frag_size = 2;
                g_custom_profile.do_fragment_http_persistent = g_custom_profile.do_fragment_http_persistent_nowait = 1;
                g_custom_profile.do_fake_packet = 1;
                g_custom_profile.fooling_flags |= FOOL_BADSUM;
                g_custom_profile.max_payload_size = 1200;
                break;
            case 'p': legacy_flags_used = 1; g_custom_profile.do_passivedpi = 1; break;
            case 'q': legacy_flags_used = 1; g_custom_profile.do_block_quic = 1; break;
            case 'r': legacy_flags_used = 1; g_custom_profile.do_host = 1; break;
            case 's': legacy_flags_used = 1; g_custom_profile.do_host_removespace = 1; break;
            case 'a': legacy_flags_used = 1; g_custom_profile.do_additional_space = g_custom_profile.do_host_removespace = 1; break;
            case 'm': legacy_flags_used = 1; g_custom_profile.do_host_mixedcase = 1; break;
            case 'f': legacy_flags_used = 1; g_custom_profile.do_fragment_http = 1; g_custom_profile.http_frag_size = (uint16_t)atoi(optarg); break;
            case 'k': legacy_flags_used = 1; g_custom_profile.do_fragment_http_persistent = 1; g_custom_profile.do_native_frag = 1; g_custom_profile.http_frag_size = (uint16_t)atoi(optarg); break;
            case 'n': legacy_flags_used = 1; g_custom_profile.do_fragment_http_persistent = g_custom_profile.do_fragment_http_persistent_nowait = g_custom_profile.do_native_frag = 1; break;
            case 'e': legacy_flags_used = 1; g_custom_profile.do_fragment_https = 1; g_custom_profile.https_frag_size = (uint16_t)atoi(optarg); break;
            case 'w': legacy_flags_used = 1; g_custom_profile.do_http_allports = 1; break;
            case 'd':
                legacy_flags_used = 1;
                if (inet_pton(AF_INET, optarg, &g_custom_profile.dnsv4_addr) == 1) {
                    g_custom_profile.do_dnsv4_redirect = 1;
                    flush_dns_cache();
                }
                break;
            case 'g':
                legacy_flags_used = 1;
                g_custom_profile.dnsv4_port = htons((uint16_t)atoi(optarg));
                break;
            case '!':
                legacy_flags_used = 1;
                if (inet_pton(AF_INET6, optarg, g_custom_profile.dnsv6_addr) == 1) {
                    g_custom_profile.do_dnsv6_redirect = 1;
                    flush_dns_cache();
                }
                break;
            case '@':
                legacy_flags_used = 1;
                g_custom_profile.dnsv6_port = htons((uint16_t)atoi(optarg));
                break;
            case 'v': legacy_flags_used = 1; g_custom_profile.do_dns_verb = g_custom_profile.do_tcp_verb = 1; break;
            case 'b':
                legacy_flags_used = 1;
                g_custom_profile.do_blacklist = 1;
                blackwhitelist_load_list(optarg);
                break;
            case ']': legacy_flags_used = 1; g_custom_profile.do_allow_no_sni = 1; break;
            case '>': legacy_flags_used = 1; g_custom_profile.do_fragment_by_sni = 1; break;
            case '$':
                legacy_flags_used = 1;
                g_custom_profile.do_fake_packet = 1;
                g_custom_profile.fooling_flags |= (FOOL_TTL | FOOL_MD5SIG | FOOL_BADSEQ);
                g_custom_profile.fake_ttl = (uint8_t)atoi(optarg);
                break;
            case '[':
                legacy_flags_used = 1;
                g_custom_profile.do_fake_packet = 1;
                g_custom_profile.min_nhops = (uint8_t)atoi(optarg);
                break;
            case '+':
                legacy_flags_used = 1;
                g_custom_profile.do_fake_packet = 1;
                g_custom_profile.fooling_flags |= (FOOL_AUTOTTL | FOOL_MD5SIG | FOOL_BADSEQ);
                break;
            case '%':
                legacy_flags_used = 1;
                g_custom_profile.do_fake_packet = 1;
                g_custom_profile.fooling_flags |= FOOL_BADSUM;
                break;
            case ')':
                legacy_flags_used = 1;
                g_custom_profile.do_fake_packet = 1;
                g_custom_profile.fooling_flags |= FOOL_BADSEQ;
                break;
            case '*':
                legacy_flags_used = 1;
                g_custom_profile.do_native_frag = 1;
                g_custom_profile.do_fragment_http_persistent = 1;
                g_custom_profile.do_fragment_http_persistent_nowait = 1;
                break;
            case '(':
                legacy_flags_used = 1;
                g_custom_profile.do_reverse_frag = 1;
                g_custom_profile.do_native_frag = 1;
                g_custom_profile.do_fragment_http_persistent = 1;
                g_custom_profile.do_fragment_http_persistent_nowait = 1;
                break;
            case '^':
                legacy_flags_used = 1;
                g_custom_profile.max_payload_size = optarg ? (uint16_t)atoi(optarg) : 1200;
                break;
            case '#':
                legacy_flags_used = 1;
                desync_load_fake_hex(optarg);
                g_custom_profile.do_fake_packet = 1;
                break;
            case '<':
                legacy_flags_used = 1;
                desync_load_fake_sni(optarg);
                g_custom_profile.do_fake_packet = 1;
                break;
            case '|':
                debug_exit = 1;
                break;
            default:
                break;
        }
    }

    if (debug_exit) {
        return 0;
    }

#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
    ensure_admin_privileges(argc, argv);
    if (mode_remove) {
        return scm_remove_service();
    }
    if (!legacy_flags_used) {
        return run_system_tray_app(selected_profile, mode_auto);
    }
#else
    (void)mode_auto;
    (void)mode_remove;
    (void)selected_profile;
#endif

    if (legacy_flags_used) {
        if (g_custom_profile.do_fragment_https && !g_custom_profile.https_frag_size)
            g_custom_profile.https_frag_size = 2;
        if (g_custom_profile.do_fragment_http && !g_custom_profile.http_frag_size)
            g_custom_profile.http_frag_size = 2;
        g_active_profile = &g_custom_profile;
    }

    g_w_filter = open_divert_handle(TURKDPI_MAIN_FILTER, 0);
    if (g_w_filter == INVALID_HANDLE_VALUE) {
        return EXIT_FAILURE;
    }

    signal(SIGINT, sigint_handler);
    flush_dns_cache();
    engine_worker_thread(NULL);
    return 0;
}
