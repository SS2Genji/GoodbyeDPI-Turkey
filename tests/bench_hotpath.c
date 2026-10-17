#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "shim/windows.h"
#include "shim/windivert.h"

int shim_captured_count = 0;
shim_captured_pkt_t shim_captured_pkts[SHIM_MAX_CAPTURED_PKTS];

/* Include goodbyedpi.c directly with renamed main for white-box testing of static hot-path kernels */
#define main goodbyedpi_app_main
#include "../src/goodbyedpi.c"
#undef main

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void build_sample_http_packet(unsigned char *buf, UINT *out_len) {
    const char *http_payload =
        "GET /api/v9/experiments?with_guild_experiments=true HTTP/1.1\r\n"
        "Accept: */*\r\n"
        "Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
        "Cache-Control: no-cache\r\n"
        "Pragma: no-cache\r\n"
        "Sec-Ch-Ua: \"Chromium\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\n"
        "Sec-Ch-Ua-Mobile: ?0\r\n"
        "Sec-Ch-Ua-Platform: \"Windows\"\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n"
        "X-Discord-Locale: tr\r\n"
        "X-Debug-Options: bugReporterEnabled\r\n"
        "Host: discord.com\r\n"
        "Connection: keep-alive\r\n\r\n";
    size_t plen = strlen(http_payload);
    memset(buf, 0, 40 + plen);
    PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)buf;
    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(buf + 20);
    ip->Version = 4;
    ip->HdrLength = 5;
    ip->TTL = 64;
    ip->Protocol = IPPROTO_TCP;
    ip->Length = htons((uint16_t)(40 + plen));
    ip->SrcAddr = htonl(0xC0A8010AU);
    ip->DstAddr = htonl(0xA29F80EB);
    tcp->SrcPort = htons(54321);
    tcp->DstPort = htons(80);
    tcp->SeqNum = htonl(100000);
    tcp->AckNum = htonl(200000);
    tcp->HdrLength = 5;
    tcp->Ack = 1;
    tcp->Psh = 1;
    tcp->Window = htons(64240);
    memcpy(buf + 40, http_payload, plen);
    *out_len = (UINT)(40 + plen);
    WINDIVERT_ADDRESS addr = {0};
    addr.Outbound = 1;
    WinDivertHelperCalcChecksums(buf, *out_len, &addr, 0);
}

/* Build a realistic TLS 1.3 ClientHello with optional padding to simulate Post-Quantum (X25519MLKEM768) >1200B */
static size_t build_sample_tls_clienthello(unsigned char *out, const char *sni, size_t extra_pad_len) {
    size_t sni_len = strlen(sni);
    /* TLS Record (5) + Handshake (4) + Version (2) + Random (32) + SessionID (1+32) +
       CipherSuites (2+4) + Compression (1+1) + ExtensionsLen (2) */
    size_t pos = 0;
    out[pos++] = 0x16; /* Handshake */
    out[pos++] = 0x03;
    out[pos++] = 0x01;
    out[pos++] = 0x00; /* Record len hi (fill later) */
    out[pos++] = 0x00; /* Record len lo */

    out[pos++] = 0x01; /* ClientHello */
    out[pos++] = 0x00;
    out[pos++] = 0x00; /* Handshake len hi */
    out[pos++] = 0x00; /* Handshake len lo */

    out[pos++] = 0x03; /* TLS 1.2 legacy version */
    out[pos++] = 0x03;

    for (int i = 0; i < 32; i++) out[pos++] = (unsigned char)(0x10 + i); /* Random */
    out[pos++] = 32; /* Session ID len */
    for (int i = 0; i < 32; i++) out[pos++] = (unsigned char)(0x40 + i);

    out[pos++] = 0x00; out[pos++] = 0x04; /* Cipher suites len = 4 */
    out[pos++] = 0x13; out[pos++] = 0x01;
    out[pos++] = 0x13; out[pos++] = 0x02;

    out[pos++] = 0x01; out[pos++] = 0x00; /* Compression methods */

    size_t ext_len_pos = pos;
    out[pos++] = 0x00; out[pos++] = 0x00; /* Extensions total length */

    /* Dummy extension 1: key_share / PQ padding before SNI to test scanning speed */
    if (extra_pad_len > 0) {
        out[pos++] = 0x00; out[pos++] = 0x33; /* key_share */
        out[pos++] = (unsigned char)((extra_pad_len >> 8) & 0xFF);
        out[pos++] = (unsigned char)(extra_pad_len & 0xFF);
        memset(out + pos, 0x5A, extra_pad_len);
        pos += extra_pad_len;
    }

    /* Extension 0x0000: server_name */
    size_t sni_ext_len = sni_len + 5;
    size_t sni_list_len = sni_len + 3;
    out[pos++] = 0x00; out[pos++] = 0x00;
    out[pos++] = (unsigned char)((sni_ext_len >> 8) & 0xFF);
    out[pos++] = (unsigned char)(sni_ext_len & 0xFF);
    out[pos++] = (unsigned char)((sni_list_len >> 8) & 0xFF);
    out[pos++] = (unsigned char)(sni_list_len & 0xFF);
    out[pos++] = 0x00; /* host_name type */
    out[pos++] = (unsigned char)((sni_len >> 8) & 0xFF);
    out[pos++] = (unsigned char)(sni_len & 0xFF);
    memcpy(out + pos, sni, sni_len);
    pos += sni_len;

    /* Fill lengths */
    size_t ext_total = pos - (ext_len_pos + 2);
    out[ext_len_pos]     = (unsigned char)((ext_total >> 8) & 0xFF);
    out[ext_len_pos + 1] = (unsigned char)(ext_total & 0xFF);

    size_t hs_total = pos - 9;
    out[7] = (unsigned char)((hs_total >> 8) & 0xFF);
    out[8] = (unsigned char)(hs_total & 0xFF);

    size_t rec_total = pos - 5;
    out[3] = (unsigned char)((rec_total >> 8) & 0xFF);
    out[4] = (unsigned char)(rec_total & 0xFF);

    return pos;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("=== GoodbyeDPI-Turkey Native Test & Micro-Benchmark Suite ===\n\n");

    /* 0. Regression tests for Task 2 (filter string memory leaks & fake_add bounds) */
    filter_string = strdup(FILTER_STRING_TEMPLATE);
    filter_passive_string = strdup(FILTER_PASSIVE_STRING_TEMPLATE);
    add_ip_id_str(42);
    add_maxpayloadsize_str(1200);
    finalize_filter_strings();
    assert(filter_string != NULL && filter_passive_string != NULL);
    free(filter_string);
    free(filter_passive_string);
    filter_string = NULL;
    filter_passive_string = NULL;

    /* Invalid hex must not leak */
    assert(fake_load_from_hex("12ZZ") == 2);
    /* Fill 30 slots and verify 31st slot returns 3 without out-of-bounds write */
    for (int i = 0; i < 30; i++) {
        assert(fake_load_from_hex("16030100") == 0);
    }
    assert(fake_load_from_hex("16030100") == 3);

    /* 1. Test & Benchmark HTTP header search (dumb_memmem / fast_memmem) */
    unsigned char http_pkt[1600];
    UINT http_pkt_len = 0;
    build_sample_http_packet(http_pkt, &http_pkt_len);
    const char *http_payload = (const char *)(http_pkt + 40);
    unsigned int http_payload_len = http_pkt_len - 40;

    char *hdr_name = NULL, *hdr_val = NULL;
    unsigned int hdr_len = 0;
    int found = find_header_and_get_info(http_payload, http_payload_len,
                                         http_host_find, &hdr_name, &hdr_val, &hdr_len);
    assert(found == TRUE);
    assert(hdr_len == strlen("discord.com"));
    assert(memcmp(hdr_val, "discord.com", hdr_len) == 0);

    const int ITERS_MEMMEM = 500000;
    uint64_t t0 = now_ns();
    volatile uintptr_t sink = 0;
    for (int i = 0; i < ITERS_MEMMEM; i++) {
        char *p = dumb_memmem(http_payload, http_payload_len, http_host_find, sizeof(http_host_find) - 1);
        sink += (uintptr_t)p;
    }
    uint64_t t1 = now_ns();
    double ns_memmem = (double)(t1 - t0) / ITERS_MEMMEM;
    printf("[BENCH] HTTP Header Pattern Search : %6.2f ns/op  (payload=%u B)\n", ns_memmem, http_payload_len);

    /* 2. Test & Benchmark TLS ClientHello SNI Extraction (including 1350B PQ-TLS ClientHello) */
    unsigned char tls_buf[2048];
    size_t tls_len = build_sample_tls_clienthello(tls_buf, "gateway.discord.gg", 1180);
    char *sni_ptr = NULL;
    unsigned int sni_len = 0;
    int sni_ok = extract_sni((const char *)tls_buf, (unsigned int)tls_len, &sni_ptr, &sni_len);
    assert(sni_ok == TRUE);
    assert(sni_len == strlen("gateway.discord.gg"));
    assert(memcmp(sni_ptr, "gateway.discord.gg", sni_len) == 0);

    const int ITERS_SNI = 500000;
    t0 = now_ns();
    for (int i = 0; i < ITERS_SNI; i++) {
        sni_ok = extract_sni((const char *)tls_buf, (unsigned int)tls_len, &sni_ptr, &sni_len);
        sink += (uintptr_t)sni_ptr + sni_len;
    }
    t1 = now_ns();
    double ns_sni = (double)(t1 - t0) / ITERS_SNI;
    printf("[BENCH] TLS PQ-ClientHello SNI Scan: %6.2f ns/op  (payload=%zu B)\n", ns_sni, tls_len);

    /* 3. Test & Benchmark UDP DNS Conntrack (dnsredir.c) */
    unsigned char dns_query[32] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'd','i','s','c','o','r','d', 0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    unsigned char dns_reply[32];
    memcpy(dns_reply, dns_query, sizeof(dns_query));
    dns_reply[2] = 0x81; dns_reply[3] = 0x80;

    uint32_t src_ip4[4] = { htonl(0xC0A8010AU), 0, 0, 0 };
    uint32_t dst_ip4[4] = { htonl(0x08080808U), 0, 0, 0 };
    conntrack_info_t cinfo;

    const int ITERS_DNS = 200000;
    t0 = now_ns();
    for (int i = 0; i < ITERS_DNS; i++) {
        uint16_t sport = htons((uint16_t)(10000 + (i & 0x7FFF)));
        int out_ok = dns_handle_outgoing(src_ip4, sport, dst_ip4, htons(53),
                                         (const char *)dns_query, sizeof(dns_query), 0);
        int in_ok = dns_handle_incoming(src_ip4, sport,
                                        (const char *)dns_reply, sizeof(dns_reply), &cinfo, 0);
        assert(out_ok == TRUE && in_ok == TRUE);
        sink += cinfo.dstport;
    }
    t1 = now_ns();
    double ns_dns = (double)(t1 - t0) / ITERS_DNS;
    printf("[BENCH] DNS Conntrack (Out+In Pair): %6.2f ns/op\n", ns_dns);

    /* 4. Test & Benchmark TCP TTL Conntrack (ttltrack.c) */
    tcp_conntrack_info_t tinfo;
    const int ITERS_TCP = 200000;
    t0 = now_ns();
    for (int i = 0; i < ITERS_TCP; i++) {
        uint16_t cport = htons((uint16_t)(20000 + (i & 0x7FFF)));
        int in_ok = tcp_handle_incoming(dst_ip4, src_ip4, htons(443), cport, 0, 117);
        int out_ok = tcp_handle_outgoing(src_ip4, dst_ip4, cport, htons(443), &tinfo, 0);
        assert(in_ok == TRUE && out_ok == TRUE);
        int fttl = tcp_get_auto_ttl(tinfo.ttl, 1, 4, 3, 10);
        sink += (uintptr_t)fttl;
    }
    t1 = now_ns();
    double ns_tcp = (double)(t1 - t0) / ITERS_TCP;
    printf("[BENCH] TCP TTL Conntrack (In+Out) : %6.2f ns/op\n", ns_tcp);

    /* 5. Test & Benchmark Checksum Recalculation on Header Edit (RFC 1624 vs Full) */
    PWINDIVERT_IPHDR ppIp = NULL;
    PWINDIVERT_TCPHDR ppTcp = NULL;
    PVOID pData = NULL;
    UINT dataLen = 0;
    WINDIVERT_ADDRESS addr = {0};
    addr.Outbound = 1;
    WinDivertHelperParsePacket(http_pkt, http_pkt_len, &ppIp, NULL, NULL, NULL, NULL, &ppTcp, NULL, &pData, &dataLen, NULL, NULL);
    assert(ppIp && ppTcp);

    /* Verify RFC 1624 incremental 16-bit and 32-bit updates match full calculation across 10,000 random edits */
    for (int i = 0; i < 10000; i++) {
        unsigned int r1 = 0, r2 = 0;
        rand_s(&r1);
        rand_s(&r2);
        uint16_t new_win = (uint16_t)(r1 & 0xFFFFu);
        uint32_t new_seq = (uint32_t)r2;

        uint16_t inc_tcp_csum = checksum_update_uint16(ppTcp->Checksum, ppTcp->Window, new_win);
        inc_tcp_csum = checksum_update_uint32(inc_tcp_csum, ppTcp->SeqNum, new_seq);

        ppTcp->Window = new_win;
        ppTcp->SeqNum = new_seq;
        WinDivertHelperCalcChecksums(http_pkt, http_pkt_len, &addr, 0);
        assert(inc_tcp_csum == ppTcp->Checksum);
    }

    const int ITERS_CSUM = 500000;
    t0 = now_ns();
    for (int i = 0; i < ITERS_CSUM; i++) {
        change_window_size(ppTcp, (unsigned int)(1024 + (i & 0xFF)));
        sink += ppTcp->Checksum;
    }
    t1 = now_ns();
    double ns_csum = (double)(t1 - t0) / ITERS_CSUM;
    printf("[BENCH] RFC 1624 Incremental Csum  : %6.2f ns/op  (pkt=%u B)\n", ns_csum, http_pkt_len);

    /* 6. Test & Benchmark Zero-Copy Blackwhitelist Lookup */
    FILE *bfp = fopen("/tmp/goodbyedpi_test_blacklist.txt", "w");
    assert(bfp != NULL);
    fprintf(bfp, "discord.com\ndiscord.gg\ndiscordapp.com\nroblox.com\nwattpad.com\n");
    fclose(bfp);
    assert(blackwhitelist_load_list("/tmp/goodbyedpi_test_blacklist.txt") == TRUE);
    assert(blackwhitelist_check_hostname("discord.com", 11) == TRUE);
    assert(blackwhitelist_check_hostname("gateway.discord.gg", 18) == TRUE);
    assert(blackwhitelist_check_hostname("CDN.DISCORDAPP.COM", 18) == TRUE);
    assert(blackwhitelist_check_hostname("notdiscord.com", 14) == FALSE);
    assert(blackwhitelist_check_hostname("google.com", 10) == FALSE);

    const int ITERS_BL = 500000;
    t0 = now_ns();
    for (int i = 0; i < ITERS_BL; i++) {
        sink += (uintptr_t)blackwhitelist_check_hostname("gateway.discord.gg", 18);
    }
    t1 = now_ns();
    double ns_bl = (double)(t1 - t0) / ITERS_BL;
    printf("[BENCH] Zero-Copy Blacklist Lookup : %6.2f ns/op\n", ns_bl);

    /* 7. Test Zero-Backup Native Fragmentation (--reverse-frag) */
    build_sample_http_packet(http_pkt, &http_pkt_len);
    WinDivertHelperParsePacket(http_pkt, http_pkt_len, &ppIp, NULL, NULL, NULL, NULL, &ppTcp, NULL, &pData, &dataLen, NULL, NULL);
    uint32_t orig_seq = ntohl(ppTcp->SeqNum);
    UINT orig_data_len = dataLen;
    shim_captured_count = 0;
    send_native_fragment((HANDLE)1, addr, (char *)http_pkt, http_pkt_len, pData, dataLen,
                         1, 0, ppIp, NULL, ppTcp, 2, 1 /* reverse_frag */);
    assert(shim_captured_count == 2);
    /* First sent packet in reverse_frag is fragment 1 (len = http_pkt_len - 2, seq = orig_seq + 2) */
    assert(shim_captured_pkts[0].len == http_pkt_len - 2);
    /* Second sent packet in reverse_frag is fragment 0 (len = 40 + 2 = 42, seq = orig_seq) */
    assert(shim_captured_pkts[1].len == 42);
    PWINDIVERT_TCPHDR f1_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[0].data + 20);
    PWINDIVERT_TCPHDR f0_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[1].data + 20);
    assert(ntohl(f1_tcp->SeqNum) == orig_seq + 2);
    assert(ntohl(f0_tcp->SeqNum) == orig_seq);
    assert(orig_data_len == http_pkt_len - 40);

    /* 8. Test Zero-Reparse Fake Packet Generation (TTL + Wrong Checksum + Wrong Seq) */
    build_sample_http_packet(http_pkt, &http_pkt_len);
    fakes_count = 0; /* use built-in fake_https_request */
    fakes_resend = 1;
    shim_captured_count = 0;
    assert(send_fake_https_request((HANDLE)1, &addr, (const char *)http_pkt, http_pkt_len,
                                   FALSE, 5 /* set_ttl */, 1 /* wrong_chksum */, 1 /* wrong_seq */) == 0);
    assert(shim_captured_count == 3);
    /* Packet 0: set_ttl=5, valid IP & TCP checksums */
    PWINDIVERT_IPHDR fk0_ip = (PWINDIVERT_IPHDR)shim_captured_pkts[0].data;
    PWINDIVERT_TCPHDR fk0_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[0].data + 20);
    assert(fk0_ip->TTL == 5);
    uint16_t fk0_ip_csum = fk0_ip->Checksum;
    uint16_t fk0_tcp_csum = fk0_tcp->Checksum;
    WinDivertHelperCalcChecksums(shim_captured_pkts[0].data, shim_captured_pkts[0].len, &addr, 0);
    assert(fk0_ip->Checksum == fk0_ip_csum);
    assert(fk0_tcp->Checksum == fk0_tcp_csum);

    /* Packet 1: wrong_chksum (damaged by -1) */
    PWINDIVERT_TCPHDR fk1_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[1].data + 20);
    assert(fk1_tcp->Checksum == htons((uint16_t)(ntohs(fk0_tcp_csum) - 1)));

    /* Packet 2: wrong_seq (-10000 seq, -66000 ack) with valid RFC 1624 TCP checksum */
    PWINDIVERT_TCPHDR fk2_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[2].data + 20);
    uint16_t fk2_tcp_csum = fk2_tcp->Checksum;
    WinDivertHelperCalcChecksums(shim_captured_pkts[2].data, shim_captured_pkts[2].len, &addr, 0);
    assert(fk2_tcp->Checksum == fk2_tcp_csum);

    if (sink == 0x123456789ULL) printf("sink=%lu\n", (unsigned long)sink);
    printf("\nAll correctness & optimization assertions passed!\n");
    return 0;
}
