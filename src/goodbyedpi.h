#include <stdint.h>

#define HOST_MAXLEN 253    // Maximum length of a hostname according to DNS standards
#define MAX_PACKET_SIZE 9016   // Maximum packet size to process

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALIGN64     __attribute__((aligned(64)))
#else
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#define ALIGN64
#endif

/**
 * RFC 1624 incremental 16-bit one's complement checksum update:
 * HC' = ~(~HC + ~m + m')
 * Works directly on network-byte-order uint16_t values due to end-around carry symmetry.
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

#if defined(__SSE4_2__)
#include <nmmintrin.h>
#endif

static inline uint32_t fast_hash_u64(uint64_t seed, uint64_t val) {
#if defined(__SSE4_2__) && defined(__x86_64__)
    return (uint32_t)_mm_crc32_u64(seed, val);
#elif defined(__SSE4_2__)
    uint32_t h = _mm_crc32_u32((uint32_t)seed, (uint32_t)val);
    return _mm_crc32_u32(h, (uint32_t)(val >> 32));
#else
    val ^= seed;
    val = (val ^ (val >> 30)) * 0xbf58476d1ce4e5b9ULL;
    val = (val ^ (val >> 27)) * 0x94d049bb133111ebULL;
    return (uint32_t)(val ^ (val >> 31));
#endif
}

#ifndef DEBUG
#define debug(...) do {} while (0)    // No-op debug function when not in debug mode
#else
#define debug(...) printf(__VA_ARGS__)    // Print debug messages when in debug mode
#endif

int main(int argc, char *argv[]);    // Main program entry point
void deinit_all();    // Clean up and free all resources before exiting
