#ifndef _SHIM_WINDIVERT_H
#define _SHIM_WINDIVERT_H

#include "windows.h"

#define WINDIVERT_LAYER_NETWORK 0
#define WINDIVERT_FLAG_SNIFF    0x0001
#define WINDIVERT_FLAG_DROP     0x0002
#define WINDIVERT_SHUTDOWN_BOTH 0x3

#define WINDIVERT_PARAM_QUEUE_LENGTH 0
#define WINDIVERT_PARAM_QUEUE_LEN    0
#define WINDIVERT_PARAM_QUEUE_TIME   1
#define WINDIVERT_PARAM_QUEUE_SIZE   2

#define WINDIVERT_BATCH_MAX     0xFF

typedef int WINDIVERT_LAYER;
typedef int WINDIVERT_PARAM;
typedef int WINDIVERT_SHUTDOWN;

typedef struct {
    INT64  Timestamp;
    UINT32 Layer:8;
    UINT32 Event:8;
    UINT32 Sniffed:1;
    UINT32 Outbound:1;
    UINT32 Loopback:1;
    UINT32 Impostor:1;
    UINT32 IPv6:1;
    UINT32 IPChecksum:1;
    UINT32 TCPChecksum:1;
    UINT32 UDPChecksum:1;
    UINT32 Reserved1:8;
    UINT32 Reserved2;
    union {
        struct {
            UINT32 IfIdx;
            UINT32 SubIfIdx;
        } Network;
        UINT64 Reserved3[2];
    };
} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

typedef struct {
    UINT8  HdrLength:4;
    UINT8  Version:4;
    UINT8  TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8  TTL;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
} WINDIVERT_IPHDR, *PWINDIVERT_IPHDR;

typedef struct {
    UINT8  TrafficClass0:4;
    UINT8  Version:4;
    UINT8  FlowLabel0:4;
    UINT8  TrafficClass1:4;
    UINT16 FlowLabel1;
    UINT16 Length;
    UINT8  NextHdr;
    UINT8  HopLimit;
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
} WINDIVERT_IPV6HDR, *PWINDIVERT_IPV6HDR;

#define WINDIVERT_IPV6HDR_GET_FLOWLABEL(hdr) \
    ((((UINT32)(hdr)->FlowLabel0) << 16) | ntohs((hdr)->FlowLabel1))

typedef struct {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT16 Reserved1:4;
    UINT16 HdrLength:4;
    UINT16 Fin:1;
    UINT16 Syn:1;
    UINT16 Rst:1;
    UINT16 Psh:1;
    UINT16 Ack:1;
    UINT16 Urg:1;
    UINT16 Reserved2:2;
    UINT16 Window;
    UINT16 Checksum;
    UINT16 UrgPtr;
} WINDIVERT_TCPHDR, *PWINDIVERT_TCPHDR;

typedef struct {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT16 Length;
    UINT16 Checksum;
} WINDIVERT_UDPHDR, *PWINDIVERT_UDPHDR;

typedef void VOID;
typedef void *LPOVERLAPPED;

/* Sent-packet recording hook for unit testing fragmentation & fake packets */
#define SHIM_MAX_CAPTURED_PKTS 16
typedef struct {
    UINT len;
    WINDIVERT_ADDRESS addr;
    unsigned char data[9016];
} shim_captured_pkt_t;

extern int shim_captured_count;
extern shim_captured_pkt_t shim_captured_pkts[SHIM_MAX_CAPTURED_PKTS];

static inline HANDLE WinDivertOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags) {
    (void)filter; (void)layer; (void)priority; (void)flags;
    return (HANDLE)0x1;
}
static inline BOOL WinDivertSetParam(HANDLE handle, WINDIVERT_PARAM param, UINT64 value) {
    (void)handle; (void)param; (void)value;
    return TRUE;
}
static inline BOOL WinDivertShutdown(HANDLE handle, WINDIVERT_SHUTDOWN how) {
    (void)handle; (void)how;
    return TRUE;
}
static inline BOOL WinDivertClose(HANDLE handle) {
    (void)handle;
    return TRUE;
}
static inline BOOL WinDivertRecv(HANDLE handle, PVOID pPacket, UINT packetLen, UINT *pRecvLen, WINDIVERT_ADDRESS *pAddr) {
    (void)handle; (void)pPacket; (void)packetLen; (void)pRecvLen; (void)pAddr;
    return FALSE;
}
static inline BOOL WinDivertRecvEx(HANDLE handle, PVOID pPacket, UINT packetLen, UINT *pRecvLen, UINT64 flags,
                                   WINDIVERT_ADDRESS *pAddr, UINT *pAddrLen, LPOVERLAPPED lpOverlapped) {
    (void)handle; (void)pPacket; (void)packetLen; (void)pRecvLen; (void)flags; (void)pAddr; (void)pAddrLen; (void)lpOverlapped;
    return FALSE;
}
static inline BOOL WinDivertSend(HANDLE handle, const VOID *pPacket, UINT packetLen, UINT *pSendLen, const WINDIVERT_ADDRESS *pAddr) {
    (void)handle;
    if (pSendLen) *pSendLen = packetLen;
    if (shim_captured_count < SHIM_MAX_CAPTURED_PKTS && packetLen <= 9016) {
        shim_captured_pkts[shim_captured_count].len = packetLen;
        if (pAddr) shim_captured_pkts[shim_captured_count].addr = *pAddr;
        memcpy(shim_captured_pkts[shim_captured_count].data, pPacket, packetLen);
        shim_captured_count++;
    }
    return TRUE;
}
static inline BOOL WinDivertSendEx(HANDLE handle, const VOID *pPacket, UINT packetLen, UINT *pSendLen, UINT64 flags,
                                   const WINDIVERT_ADDRESS *pAddr, UINT addrLen, LPOVERLAPPED lpOverlapped) {
    (void)flags; (void)lpOverlapped;
    UINT count = addrLen / sizeof(WINDIVERT_ADDRESS);
    const unsigned char *ptr = (const unsigned char *)pPacket;
    UINT remaining = packetLen;
    for (UINT i = 0; i < count && remaining >= 20; i++) {
        UINT8 ver = ptr[0] >> 4;
        UINT pkt_len = 0;
        if (ver == 4) {
            pkt_len = ntohs(*(const UINT16 *)(ptr + 2));
        } else if (ver == 6 && remaining >= 40) {
            pkt_len = 40 + ntohs(*(const UINT16 *)(ptr + 4));
        }
        if (pkt_len == 0 || pkt_len > remaining) break;
        WinDivertSend(handle, ptr, pkt_len, NULL, &pAddr[i]);
        ptr += pkt_len;
        remaining -= pkt_len;
    }
    if (pSendLen) *pSendLen = packetLen - remaining;
    return TRUE;
}

static inline BOOL WinDivertHelperParsePacket(
    const VOID *pPacket, UINT packetLen,
    PWINDIVERT_IPHDR *ppIpHdr, PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    UINT8 *pProtocol, void **ppIcmpHdr, void **ppIcmpv6Hdr,
    PWINDIVERT_TCPHDR *ppTcpHdr, PWINDIVERT_UDPHDR *ppUdpHdr,
    PVOID *ppData, UINT *pDataLen, PVOID *ppNext, UINT *pNextLen)
{
    (void)pProtocol; (void)ppIcmpHdr; (void)ppIcmpv6Hdr;
    if (ppIpHdr) *ppIpHdr = NULL;
    if (ppIpv6Hdr) *ppIpv6Hdr = NULL;
    if (ppTcpHdr) *ppTcpHdr = NULL;
    if (ppUdpHdr) *ppUdpHdr = NULL;
    if (ppData) *ppData = NULL;
    if (pDataLen) *pDataLen = 0;
    if (ppNext) *ppNext = NULL;
    if (pNextLen) *pNextLen = 0;

    if (!pPacket || packetLen < 20) return FALSE;
    const uint8_t *pkt = (const uint8_t *)pPacket;
    uint8_t ver = pkt[0] >> 4;
    size_t l3_len = 0;
    size_t total_len = packetLen;
    uint8_t proto = 0;

    if (ver == 4) {
        PWINDIVERT_IPHDR ip4 = (PWINDIVERT_IPHDR)pPacket;
        l3_len = (size_t)ip4->HdrLength * 4;
        size_t ip4_len = ntohs(ip4->Length);
        if (l3_len < 20 || packetLen < l3_len) return FALSE;
        if (ip4_len >= l3_len && ip4_len <= packetLen) total_len = ip4_len;
        if (ppIpHdr) *ppIpHdr = ip4;
        proto = ip4->Protocol;
    } else if (ver == 6) {
        if (packetLen < 40) return FALSE;
        PWINDIVERT_IPV6HDR ip6 = (PWINDIVERT_IPV6HDR)pPacket;
        l3_len = 40;
        size_t ip6_len = 40 + (size_t)ntohs(ip6->Length);
        if (ip6_len <= packetLen) total_len = ip6_len;
        if (ppIpv6Hdr) *ppIpv6Hdr = ip6;
        proto = ip6->NextHdr;
    } else {
        return FALSE;
    }

    size_t l4_len = 0;
    if (proto == IPPROTO_TCP) {
        if (total_len < l3_len + 20) return FALSE;
        PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(pkt + l3_len);
        l4_len = (size_t)tcp->HdrLength * 4;
        if (l4_len < 20 || total_len < l3_len + l4_len) return FALSE;
        if (ppTcpHdr) *ppTcpHdr = tcp;
    } else if (proto == IPPROTO_UDP) {
        if (total_len < l3_len + 8) return FALSE;
        PWINDIVERT_UDPHDR udp = (PWINDIVERT_UDPHDR)(pkt + l3_len);
        l4_len = 8;
        if (ppUdpHdr) *ppUdpHdr = udp;
    } else {
        return FALSE;
    }

    UINT payload_len = (UINT)(total_len - l3_len - l4_len);
    if (payload_len > 0) {
        if (ppData) *ppData = (PVOID)(pkt + l3_len + l4_len);
        if (pDataLen) *pDataLen = payload_len;
    }
    if (packetLen > total_len) {
        if (ppNext) *ppNext = (PVOID)(pkt + total_len);
        if (pNextLen) *pNextLen = (UINT)(packetLen - total_len);
    }
    return TRUE;
}

static inline uint16_t shim_ones_complement_sum(uint32_t sum, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    while (len >= 2) {
        uint16_t w = ((uint16_t)p[0] << 8) | p[1];
        sum += w;
        p += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += ((uint16_t)p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static inline BOOL WinDivertHelperCalcChecksums(VOID *pPacket, UINT packetLen, WINDIVERT_ADDRESS *pAddr, UINT64 flags) {
    (void)flags;
    PWINDIVERT_IPHDR ip4 = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    PWINDIVERT_TCPHDR tcp = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    if (!WinDivertHelperParsePacket(pPacket, packetLen, &ip4, &ip6, NULL, NULL, NULL, &tcp, &udp, NULL, NULL, NULL, NULL))
        return FALSE;

    size_t l3_len = ip4 ? (size_t)ip4->HdrLength * 4 : 40;
    size_t l4_total = packetLen - l3_len;

    if (ip4) {
        ip4->Checksum = 0;
        ip4->Checksum = htons(shim_ones_complement_sum(0, ip4, l3_len));
        if (pAddr) pAddr->IPChecksum = 1;
    }

    uint32_t pseudo = 0;
    if (ip4) {
        const uint8_t *s = (const uint8_t *)&ip4->SrcAddr;
        const uint8_t *d = (const uint8_t *)&ip4->DstAddr;
        pseudo += ((uint16_t)s[0] << 8) | s[1];
        pseudo += ((uint16_t)s[2] << 8) | s[3];
        pseudo += ((uint16_t)d[0] << 8) | d[1];
        pseudo += ((uint16_t)d[2] << 8) | d[3];
        pseudo += ip4->Protocol;
        pseudo += (uint16_t)l4_total;
    } else if (ip6) {
        const uint8_t *s = (const uint8_t *)ip6->SrcAddr;
        const uint8_t *d = (const uint8_t *)ip6->DstAddr;
        for (int i = 0; i < 16; i += 2) {
            pseudo += ((uint16_t)s[i] << 8) | s[i + 1];
            pseudo += ((uint16_t)d[i] << 8) | d[i + 1];
        }
        pseudo += ip6->NextHdr;
        pseudo += (uint16_t)l4_total;
    }

    if (tcp) {
        tcp->Checksum = 0;
        tcp->Checksum = htons(shim_ones_complement_sum(pseudo, tcp, l4_total));
        if (pAddr) pAddr->TCPChecksum = 1;
    } else if (udp) {
        udp->Checksum = 0;
        uint16_t csum = shim_ones_complement_sum(pseudo, udp, l4_total);
        udp->Checksum = htons(csum == 0 ? 0xFFFFu : csum);
        if (pAddr) pAddr->UDPChecksum = 1;
    }
    return TRUE;
}

#endif /* _SHIM_WINDIVERT_H */
