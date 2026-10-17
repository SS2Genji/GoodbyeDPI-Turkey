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

/* Include main.c directly with renamed main for white-box testing of static hot-path kernels */
#define main turkdpi_app_main
#include "../src/main.c"
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
    size_t pos = 0;
    out[pos++] = 0x16; /* Handshake */
    out[pos++] = 0x03;
    out[pos++] = 0x01;
    out[pos++] = 0x00;
    out[pos++] = 0x00;

    out[pos++] = 0x01; /* ClientHello */
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x00;

    out[pos++] = 0x03;
    out[pos++] = 0x03;

    for (int i = 0; i < 32; i++) out[pos++] = (unsigned char)(0x10 + i);
    out[pos++] = 32;
    for (int i = 0; i < 32; i++) out[pos++] = (unsigned char)(0x40 + i);

    out[pos++] = 0x00; out[pos++] = 0x04;
    out[pos++] = 0x13; out[pos++] = 0x01;
    out[pos++] = 0x13; out[pos++] = 0x02;

    out[pos++] = 0x01; out[pos++] = 0x00;

    size_t ext_len_pos = pos;
    out[pos++] = 0x00; out[pos++] = 0x00;

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
    out[pos++] = 0x00;
    out[pos++] = (unsigned char)((sni_len >> 8) & 0xFF);
    out[pos++] = (unsigned char)(sni_len & 0xFF);
    memcpy(out + pos, sni, sni_len);
    pos += sni_len;

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
    printf("=== TurkDPI v2.0 Native Test & Micro-Benchmark Suite ===\n\n");

    /* 0. Regression tests for custom fake packet bounds & memory safety */
    desync_cleanup();
    assert(desync_load_fake_hex("12ZZ") < 0);
    for (int i = 0; i < 30; i++) {
        assert(desync_load_fake_hex("16030100") == 0);
    }
    assert(desync_load_fake_hex("16030100") < 0);
    desync_cleanup();
    desync_init_defaults();

    /* 1. Test & Benchmark HTTP header search (fast_memmem) */
    unsigned char http_pkt[1600];
    UINT http_pkt_len = 0;
    build_sample_http_packet(http_pkt, &http_pkt_len);
    const char *http_payload = (const char *)(http_pkt + 40);
    unsigned int http_payload_len = http_pkt_len - 40;

    char *hdr_name = NULL, *hdr_val = NULL;
    unsigned int hdr_len = 0;
    int found = find_header_and_get_info(http_payload, http_payload_len,
                                         "\r\nHost: ", &hdr_name, &hdr_val, &hdr_len);
    assert(found == TRUE);
    assert(hdr_len == strlen("discord.com"));
    assert(memcmp(hdr_val, "discord.com", hdr_len) == 0);

    const int ITERS_MEMMEM = 500000;
    uint64_t t0 = now_ns();
    volatile uintptr_t sink = 0;
    for (int i = 0; i < ITERS_MEMMEM; i++) {
        char *p = fast_memmem(http_payload, http_payload_len, "\r\nHost: ", 8);
        sink += (uintptr_t)p;
    }
    uint64_t t1 = now_ns();
    double ns_memmem = (double)(t1 - t0) / ITERS_MEMMEM;
    printf("[BENCH] HTTP Header Pattern Search : %6.2f ns/op  (payload=%u B)\n", ns_memmem, http_payload_len);

    /* 2. Test & Benchmark TLS ClientHello SNI & Offset Extraction (1297B PQ-TLS ClientHello) */
    unsigned char tls_buf[2048];
    size_t tls_len = build_sample_tls_clienthello(tls_buf, "gateway.discord.gg", 1180);
    sni_info_t sni = { NULL, 0, 0 };
    int sni_ok = extract_sni_info((const char *)tls_buf, (unsigned int)tls_len, &sni);
    assert(sni_ok == 1);
    assert(sni.host_len == strlen("gateway.discord.gg"));
    assert(memcmp(sni.host_ptr, "gateway.discord.gg", sni.host_len) == 0);
    assert(sni.host_ptr == (const char *)tls_buf + sni.host_offset);

    const int ITERS_SNI = 500000;
    t0 = now_ns();
    for (int i = 0; i < ITERS_SNI; i++) {
        sni_ok = extract_sni_info((const char *)tls_buf, (unsigned int)tls_len, &sni);
        sink += (uintptr_t)sni.host_ptr + sni.host_len + sni.host_offset;
    }
    t1 = now_ns();
    double ns_sni = (double)(t1 - t0) / ITERS_SNI;
    printf("[BENCH] TLS PQ-ClientHello SNI Scan: %6.2f ns/op  (payload=%zu B)\n", ns_sni, tls_len);

    /* 3. Test & Benchmark UDP DNS Conntrack (conntrack.c) */
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
        int in_ok = dns_handle_incoming(dst_ip4, htons(1253), src_ip4, sport,
                                        (const char *)dns_reply, sizeof(dns_reply), &cinfo, 0);
        assert(out_ok == 1 && in_ok == 1);
        sink += cinfo.dstport;
    }
    t1 = now_ns();
    double ns_dns = (double)(t1 - t0) / ITERS_DNS;
    printf("[BENCH] DNS Conntrack (Out+In Pair): %6.2f ns/op\n", ns_dns);

    /* 4. Test & Benchmark TCP TTL Conntrack (conntrack.c) */
    tcp_conntrack_info_t tinfo;
    const int ITERS_TCP = 200000;
    t0 = now_ns();
    for (int i = 0; i < ITERS_TCP; i++) {
        uint16_t cport = htons((uint16_t)(20000 + (i & 0x7FFF)));
        int in_ok = tcp_handle_incoming(dst_ip4, htons(443), src_ip4, cport, 0, 117);
        int out_ok = tcp_handle_outgoing(src_ip4, cport, dst_ip4, htons(443), &tinfo, 0);
        assert(in_ok == 1 && out_ok == 1);
        uint8_t fttl = tcp_get_auto_ttl(tinfo.ttl, 1, 4, 3, 10);
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
    assert(blackwhitelist_load_list("/tmp/goodbyedpi_test_blacklist.txt") == true);
    assert(blackwhitelist_check_hostname("discord.com", 11) == true);
    assert(blackwhitelist_check_hostname("gateway.discord.gg", 18) == true);
    assert(blackwhitelist_check_hostname("CDN.DISCORDAPP.COM", 18) == true);
    assert(blackwhitelist_check_hostname("notdiscord.com", 14) == false);
    assert(blackwhitelist_check_hostname("google.com", 10) == false);

    const int ITERS_BL = 500000;
    t0 = now_ns();
    for (int i = 0; i < ITERS_BL; i++) {
        sink += (uintptr_t)blackwhitelist_check_hostname("gateway.discord.gg", 18);
    }
    t1 = now_ns();
    double ns_bl = (double)(t1 - t0) / ITERS_BL;
    printf("[BENCH] Zero-Copy Blacklist Lookup : %6.2f ns/op\n", ns_bl);

    /* 7. Test 3-Way SNI-Midpoint Reverse Disorder (Zapret midsld / ByeDPI split-by-sni) */
    build_sample_http_packet(http_pkt, &http_pkt_len);
    WinDivertHelperParsePacket(http_pkt, http_pkt_len, &ppIp, NULL, NULL, NULL, NULL, &ppTcp, NULL, &pData, &dataLen, NULL, NULL);
    uint32_t orig_seq = ntohl(ppTcp->SeqNum);
    shim_captured_count = 0;
    assert(desync_send_tcp_split((HANDLE)1, &addr, (const char *)http_pkt, http_pkt_len,
                                 pData, dataLen, 1, 0, ppIp, NULL, ppTcp,
                                 2u, 25u, 1 /* reverse disorder */) == 0);
    assert(shim_captured_count == 3);
    /* Reverse disorder order:
     *   Packet 0: [25..dataLen]  (seq = orig_seq + 25)
     *   Packet 1: [2..25]        (seq = orig_seq + 2)
     *   Packet 2: [0..2]         (seq = orig_seq + 0)
     */
    PWINDIVERT_TCPHDR s0_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[0].data + 20);
    PWINDIVERT_TCPHDR s1_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[1].data + 20);
    PWINDIVERT_TCPHDR s2_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[2].data + 20);
    assert(ntohl(s0_tcp->SeqNum) == orig_seq + 25);
    assert(ntohl(s1_tcp->SeqNum) == orig_seq + 2);
    assert(ntohl(s2_tcp->SeqNum) == orig_seq);
    assert(shim_captured_pkts[0].len == 40 + (dataLen - 25));
    assert(shim_captured_pkts[1].len == 40 + 23);
    assert(shim_captured_pkts[2].len == 40 + 2);

    /* 8. Test Multi-Fooling Decoy Generation (FOOL_MD5SIG + FOOL_TTL + FOOL_BADSEQ + FOOL_BADSUM) */
    build_sample_http_packet(http_pkt, &http_pkt_len);
    shim_captured_count = 0;
    assert(desync_send_fake_tcp((HANDLE)1, &addr, (const char *)http_pkt, http_pkt_len,
                                0, 5 /* TTL */, FOOL_MD5SIG | FOOL_BADSUM | FOOL_BADSEQ, 1) == 0);
    assert(shim_captured_count == 3);
    PWINDIVERT_IPHDR fk0_ip = (PWINDIVERT_IPHDR)shim_captured_pkts[0].data;
    PWINDIVERT_TCPHDR fk0_tcp = (PWINDIVERT_TCPHDR)(shim_captured_pkts[0].data + 20);
    assert(fk0_ip->TTL == 5);
    /* Verify TCP MD5 Signature Option (Kind=19, Len=18) was attached (+5 words = HdrLength 10) */
    assert(fk0_tcp->HdrLength == 10);
    assert(shim_captured_pkts[0].data[40] == 19 && shim_captured_pkts[0].data[41] == 18);

    /* 9. Test Discord Voice / WebRTC UDP Desync (74B Discord IP Discovery Packet) */
    unsigned char udp_pkt[42 + 74];
    memset(udp_pkt, 0, sizeof(udp_pkt));
    PWINDIVERT_IPHDR u_ip = (PWINDIVERT_IPHDR)udp_pkt;
    PWINDIVERT_UDPHDR u_udp = (PWINDIVERT_UDPHDR)(udp_pkt + 20);
    unsigned char *u_pld = udp_pkt + 28;
    u_ip->Version = 4; u_ip->HdrLength = 5; u_ip->TTL = 64; u_ip->Protocol = IPPROTO_UDP;
    u_ip->Length = htons(28 + 74);
    u_udp->SrcPort = htons(55000); u_udp->DstPort = htons(50005); u_udp->Length = htons(8 + 74);
    /* Discord IP Discovery header: 0x00 0x01 0x00 0x46 */
    u_pld[0] = 0x00; u_pld[1] = 0x01; u_pld[2] = 0x00; u_pld[3] = 0x46;
    assert(desync_is_discord_or_webrtc_udp(u_udp->SrcPort, u_udp->DstPort, u_pld, 74) == 1);

    shim_captured_count = 0;
    assert(desync_send_udp_fake((HANDLE)1, &addr, (const char *)udp_pkt, 28 + 74, 0) == 0);
    assert(shim_captured_count == 1);
    PWINDIVERT_IPHDR d_uip = (PWINDIVERT_IPHDR)shim_captured_pkts[0].data;
    assert(d_uip->TTL == 3);
    assert(shim_captured_pkts[0].len == 28 + 8);

    /* 10. Test Probe TLS 1.3 ClientHello Builder & Raw DNS Parser (BTK Sinkhole Filter) */
    unsigned char probe_ch[512];
    int probe_ch_len = probe_build_tls_client_hello(probe_ch, sizeof(probe_ch), "discord.com");
    assert(probe_ch_len > 100);
    sni_info_t probe_sni = { NULL, 0, 0 };
    assert(extract_sni_info((const char *)probe_ch, (unsigned int)probe_ch_len, &probe_sni) == 1);
    assert(probe_sni.host_len == 11 && memcmp(probe_sni.host_ptr, "discord.com", 11) == 0);

    unsigned char qdns[256];
    int qdns_len = probe_build_dns_query(qdns, sizeof(qdns), "discord.com", 0xBEEF);
    assert(qdns_len == 29);

    if (sink == 0x123456789ULL) printf("sink=%lu\n", (unsigned long)sink);
    desync_cleanup();
    printf("\nAll TurkDPI v2.0 correctness & optimization assertions passed!\n");
    return 0;
}
