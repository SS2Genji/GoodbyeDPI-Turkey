#ifndef _DNSREDIR_H
#define _DNSREDIR_H
#include <stdint.h>

// Connection tracking information for DNS requests
typedef struct conntrack_info {
    uint8_t  is_ipv6;      // Flag indicating if IPv6 (1) or IPv4 (0)
    uint32_t srcip[4];     // Source IP address (supports both IPv4 and IPv6)
    uint16_t srcport;      // Source port
    uint32_t dstip[4];     // Destination IP address (supports both IPv4 and IPv6)
    uint16_t dstport;      // Destination port
} conntrack_info_t;

// Helper function to copy IPv4 address (uses only the first element in the array)
inline static void ipv4_copy_addr(uint32_t *dst, const uint32_t *src) {
    memcpy(dst, src, sizeof(uint32_t));
    memset(dst + 1, 0, sizeof(uint32_t) * 3);
}

// Helper function to copy IPv6 address (uses all 4 elements in the array)
inline static void ipv6_copy_addr(uint32_t *dst, const uint32_t *src) {
    memcpy(dst, src, sizeof(uint32_t) * 4);
}

// Handle incoming DNS packet and fill connection info
int dns_handle_incoming(const uint32_t *srcip, const uint16_t srcport,
                        const char *packet_data, const UINT packet_dataLen,
                        conntrack_info_t *conn_info, const uint8_t is_ipv6);

// Handle outgoing DNS packet
int dns_handle_outgoing(const uint32_t *srcip, const uint16_t srcport,
                        const uint32_t *dstip, const uint16_t dstport,
                        const char *packet_data, const UINT packet_dataLen,
                        const uint8_t is_ipv6
                       );

// Clear the DNS cache
void flush_dns_cache();

// Check if packet is a DNS packet
int dns_is_dns_packet(const char *packet_data, const UINT packet_dataLen, const int outgoing);
#endif
