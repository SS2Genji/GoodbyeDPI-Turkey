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

    printf("[*] Yonetici yetkisi (UAC) isteniyor...\n");
    SHELLEXECUTEINFOA sei;
    memset(&sei, 0, sizeof(sei));
    sei.cbSize       = sizeof(sei);
    sei.lpVerb       = "runas";
    sei.lpFile       = exe_path;
    sei.lpParameters = params[0] ? params : NULL;
    sei.lpDirectory  = exe_dir;
    sei.nShow        = SW_SHOWNORMAL;

    if (ShellExecuteExA(&sei)) {
        exit(EXIT_SUCCESS);
    }
}

static int scm_remove_service(void) {
    printf("\n[*] GoodbyeDPI Windows Hizmeti ve WinDivert surucusu kaldiriliyor...\n");
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
    flush_dns_cache();
    printf("[+] GoodbyeDPI hizmeti ve WinDivert suruculeri basariyla kaldirildi.\n");
    return 0;
}

static int scm_install_service(int profile_idx) {
    if (profile_idx < 0 || profile_idx >= TURKDPI_NUM_PROFILES) profile_idx = 0;

    char exe_path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exe_path, MAX_PATH)) {
        printf("[!] HATA: Calistirilabilir dosya yolu alinamadi.\n");
        return -1;
    }

    scm_remove_service();
    Sleep(300);

    char bin_path[MAX_PATH + 64];
    snprintf(bin_path, sizeof(bin_path), "\"%s\" --service --profile %d", exe_path, profile_idx);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("[!] HATA: Service Control Manager acilamadi (Hata: %lu).\n", (unsigned long)GetLastError());
        return -1;
    }

    SC_HANDLE svc = CreateServiceA(
        scm,
        SERVICE_NAME,
        "GoodbyeDPI-Turkey (TurkDPI Engine)",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        bin_path,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!svc) {
        printf("[!] HATA: Hizmet olusturulamadi (Hata: %lu).\n", (unsigned long)GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }

    StartServiceA(svc, 0, NULL);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    flush_dns_cache();

    printf("\n[+] BASARILI! GoodbyeDPI Windows Hizmeti kuruldu ve baslatildi!\n");
    printf("    Aktif Profil : [Profil %d] %s\n", profile_idx, g_turkdpi_profiles[profile_idx].name);
    printf("    Baslangic    : Otomatik (Her bilgisayari actiginizda arka planda calisir)\n");
    return 0;
}

static void scm_show_status(void) {
    printf("\n============================================================================\n");
    printf("  TurkDPI Hizmet ve Canli Discord Baglanti Durumu\n");
    printf("============================================================================\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st;
            if (QueryServiceStatus(svc, &st)) {
                printf("  [*] Windows Hizmeti (GoodbyeDPI): %s\n",
                       st.dwCurrentState == SERVICE_RUNNING ? "AKTIF (CALISIYOR)" : "DURDURULMUS");
            }
            CloseServiceHandle(svc);
        } else {
            printf("  [*] Windows Hizmeti (GoodbyeDPI): KURULU DEGIL\n");
        }
        CloseServiceHandle(scm);
    }

    uint32_t dip = probe_resolve_domain("discord.com", 0xE8879FA2u);
    int ms = probe_test_https_target(dip, 443, "discord.com", 2000);
    if (ms > 0) {
        printf("  [+] Discord TLS 1.3 Erisimi     : ACIK (%d ms)\n", ms);
    } else {
        printf("  [-] Discord TLS 1.3 Erisimi     : KAPALI (Bir profil baslatin veya [A] Otomatik Algilama secin)\n");
    }
    printf("============================================================================\n");
}

/* Windows Service Control Dispatcher glue */
static SERVICE_STATUS        g_svc_status;
static SERVICE_STATUS_HANDLE g_svc_status_handle;

static void WINAPI svc_ctrl_handler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_svc_status.dwCurrentState  = SERVICE_STOP_PENDING;
        g_svc_status.dwWin32ExitCode = 0;
        SetServiceStatus(g_svc_status_handle, &g_svc_status);
        deinit_all();
        g_svc_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_svc_status_handle, &g_svc_status);
    }
}

static void WINAPI svc_main(DWORD dwArgc, LPSTR *lpszArgv) {
    (void)dwArgc; (void)lpszArgv;
    g_svc_status_handle = RegisterServiceCtrlHandlerA(SERVICE_NAME, svc_ctrl_handler);
    if (!g_svc_status_handle) return;

    g_svc_status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwCurrentState     = SERVICE_RUNNING;
    g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_svc_status_handle, &g_svc_status);

    g_w_filter = open_divert_handle(TURKDPI_MAIN_FILTER, 0);
    if (g_w_filter != INVALID_HANDLE_VALUE) {
        flush_dns_cache();
        engine_worker_thread(NULL);
    }

    g_svc_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_svc_status_handle, &g_svc_status);
}

static int run_as_service(void) {
    char svc_name[] = SERVICE_NAME;
    SERVICE_TABLE_ENTRYA ste[] = {
        { svc_name, (LPSERVICE_MAIN_FUNCTIONA)svc_main },
        { NULL, NULL }
    };
    return StartServiceCtrlDispatcherA(ste);
}

#endif /* _WIN32 */

/* ============================================================================
 * 4. Interactive Turkish Console Menu (Zero Batch Script Dependency)
 * ============================================================================ */
static int run_interactive_console(void) {
#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
    SetConsoleTitleA("TurkDPI v2.0 - Akilli DPI & Discord Erisim Motoru");
#endif
    char line[64];

    for (;;) {
        printf("\n============================================================================\n");
        printf("  TurkDPI v" TURKDPI_VERSION " — Yeni Nesil Akilli DPI & Discord Ses/Web Motoru\n");
        printf("  (Zapret MD5Sig + ByeDPI SNI-MidSplit + Dual-Stack DNS + Discord UDP Ses)\n");
        printf("============================================================================\n\n");
        printf("  [A] OTOMATIK ALGILAMA (ISS'niz icin en hizli profili bul ve calistir)\n\n");
        printf("  --- Gecici Calistir (Pencere Kapaninca Durur) ----------------------------\n");
        for (int i = 0; i < TURKDPI_NUM_PROFILES; i++) {
            printf("  [%d] %s\n", i, g_turkdpi_profiles[i].name);
        }
        printf("\n  --- Windows Hizmeti (Servis) Yonetimi ------------------------------------\n");
        printf("  [S] Hizmet Olarak Kur (Otomatik algilar ve her acilista baslatir)\n");
        printf("  [R] Hizmeti ve WinDivert Surucusunu Tamamen Kaldir (REVERT)\n");
        printf("  [D] Durum Kontrolu ve Canli Discord Baglanti Testi\n");
        printf("  [Q] Cikis\n\n");
        printf("Seciminiz [A/0-6/S/R/D/Q]: ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) return -1;
        char ch = 0;
        for (int i = 0; line[i]; i++) {
            if (!isspace((unsigned char)line[i])) { ch = (char)toupper((unsigned char)line[i]); break; }
        }

        if (ch == 'Q') {
            return -1;
        }
#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
        if (ch == 'R') {
            scm_remove_service();
            continue;
        }
        if (ch == 'D') {
            scm_show_status();
            continue;
        }
        if (ch == 'S') {
            printf("\n[*] Kurulum icin en uygun ISS profili otomatik tespit ediliyor...\n");
            g_w_filter = open_divert_handle(TURKDPI_MAIN_FILTER, 0);
            if (g_w_filter == INVALID_HANDLE_VALUE) continue;
            HANDLE h_thread = CreateThread(NULL, 0, engine_worker_thread, NULL, 0, NULL);
            int best = probe_find_best_profile(&g_active_profile);
            deinit_all();
            if (h_thread) { WaitForSingleObject(h_thread, 1000); CloseHandle(h_thread); }
            g_exiting = 0;
            scm_install_service(best);
            continue;
        }
#endif
        if (ch == 'A') {
            return -100; /* Trigger Auto-Probe + Live Run */
        }
        if (ch >= '0' && ch <= '6') {
            return (ch - '0');
        }
    }
}

/* ============================================================================
 * 5. CLI Argument Parser & Entry Point
 * ============================================================================ */
static struct option long_options[] = {
    {"auto",        no_argument,       0, 'A'},
    {"interactive", no_argument,       0, 'I'},
    {"install",     optional_argument, 0, 'S'},
    {"remove",      no_argument,       0, 'R'},
    {"status",      no_argument,       0, 'D'},
    {"service",     no_argument,       0, 'W'},
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

    int mode_auto        = 0;
    int mode_interactive = (argc == 1);
    int mode_install     = 0;
    int mode_remove      = 0;
    int mode_status      = 0;
    int mode_service     = 0;
    int selected_profile = -1;
    int legacy_flags_used = 0;
    int debug_exit       = 0;

    if (argc > 1) {
        /* Start with clean custom profile when legacy flags are passed,
         * but always keep SNI-midpoint split and Discord Voice UDP desync enabled! */
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
    while ((opt = getopt_long(argc, argv, "123456789pqrsaf:e:mwk:nAISRDWP:d:g:v:b:z:i:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'A': mode_auto = 1; mode_interactive = 0; break;
            case 'I': mode_interactive = 1; break;
            case 'S':
                mode_install = 1;
                mode_interactive = 0;
                if (optarg) {
                    selected_profile = atoi(optarg);
                } else if (optind < argc && isdigit((unsigned char)argv[optind][0])) {
                    selected_profile = atoi(argv[optind++]);
                } else {
                    mode_auto = 1; /* Auto-detect best profile before installing service if none specified */
                }
                break;
            case 'R': mode_remove = 1; mode_interactive = 0; break;
            case 'D': mode_status = 1; mode_interactive = 0; break;
            case 'W': mode_service = 1; mode_interactive = 0; break;
            case 'P':
                selected_profile = atoi(optarg);
                if (selected_profile < 0 || selected_profile >= TURKDPI_NUM_PROFILES) selected_profile = 0;
                mode_interactive = 0;
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
                mode_interactive = 0;
                break;
            default:
                break;
        }
    }

    if (debug_exit) {
        printf("TurkDPI Debug Exit OK\n");
        return 0;
    }

#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
    if (!mode_service && GetConsoleWindow() != NULL) {
        ensure_admin_privileges(argc, argv);
    }
    if (mode_remove) {
        return scm_remove_service();
    }
    if (mode_status) {
        scm_show_status();
        return 0;
    }
    if (mode_install && !mode_auto) {
        return scm_install_service(selected_profile >= 0 ? selected_profile : 0);
    }
#else
    (void)mode_auto;
    (void)mode_install;
    (void)mode_remove;
    (void)mode_status;
    (void)mode_service;
#endif

    if (mode_interactive) {
        int choice = run_interactive_console();
        if (choice == -100) {
            mode_auto = 1;
        } else if (choice >= 0 && choice < TURKDPI_NUM_PROFILES) {
            selected_profile = choice;
        } else {
            return 0;
        }
    }

    if (selected_profile >= 0 && selected_profile < TURKDPI_NUM_PROFILES) {
        g_active_profile = &g_turkdpi_profiles[selected_profile];
    } else if (legacy_flags_used) {
        if (g_custom_profile.do_fragment_https && !g_custom_profile.https_frag_size)
            g_custom_profile.https_frag_size = 2;
        if (g_custom_profile.do_fragment_http && !g_custom_profile.http_frag_size)
            g_custom_profile.http_frag_size = 2;
        g_active_profile = &g_custom_profile;
    } else {
        g_active_profile = &g_turkdpi_profiles[0];
    }

#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
    if (mode_service || (GetConsoleWindow() == NULL && !mode_auto)) {
        if (run_as_service()) {
            return 0;
        }
    }
#endif

    g_w_filter = open_divert_handle(TURKDPI_MAIN_FILTER, 0);
    if (g_w_filter == INVALID_HANDLE_VALUE) {
        return EXIT_FAILURE;
    }

    signal(SIGINT, sigint_handler);
    flush_dns_cache();

#if defined(_WIN32) && !defined(_SHIM_WINDOWS_H)
    if (mode_auto) {
        HANDLE h_thread = CreateThread(NULL, 0, engine_worker_thread, NULL, 0, NULL);
        int best_idx = probe_find_best_profile(&g_active_profile);

        if (mode_install) {
            deinit_all();
            if (h_thread) { WaitForSingleObject(h_thread, 1000); CloseHandle(h_thread); }
            g_exiting = 0;
            return scm_install_service(best_idx);
        }

        printf("\n[*] TurkDPI su anda [Profil %d] ile aktif olarak calisiyor!\n", best_idx);
        printf("    Discord (Web + Sesli Sohbet) ve tum engelli sitelere erisebilirsiniz.\n");
        printf("    Durdurmak icin bu pencereyi kapatin veya Ctrl+C tuslarina basin.\n\n");
        if (h_thread) {
            WaitForSingleObject(h_thread, INFINITE);
            CloseHandle(h_thread);
        }
        return 0;
    }
#endif

    printf("\n============================================================================\n");
    printf("  [+] TurkDPI v" TURKDPI_VERSION " Aktif — Filtre Calisiyor!\n");
    printf("  [+] Aktif Profil : %s\n", g_active_profile->name);
    printf("  [+] Hedef ISS    : %s\n", g_active_profile->isp_hint);
    printf("  [+] Ozellikler   : SNI-MidSplit=%d | Reverse=%d | Fake=%d (0x%02X) | UDP-Ses=%d | DNS=%d\n",
           g_active_profile->do_split_sni,
           g_active_profile->do_reverse_frag,
           g_active_profile->do_fake_packet,
           g_active_profile->fooling_flags,
           g_active_profile->do_udp_fake,
           g_active_profile->do_dnsv4_redirect);
    printf("============================================================================\n");
    printf("  Discord (Web & Ses) ve diger uygulamalar icin DPI engeli kaldirildi.\n");
    printf("  Kapatmak icin Ctrl+C tuslarina basin veya pencereyi kapatin.\n\n");

    engine_worker_thread(NULL);
    return 0;
}
