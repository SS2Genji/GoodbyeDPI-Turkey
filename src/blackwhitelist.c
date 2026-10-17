/*
 * Zero-Copy Case-Insensitive Domain Blacklist for GoodbyeDPI
 *
 * Uses an open-addressed hash table keyed by lowercase FNV-1a/CRC32C hash
 * and length so blackwhitelist_check_hostname() performs subdomain suffix
 * lookups directly on the packet buffer without copying or strchr loops.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "goodbyedpi.h"
#include "utils/getline.h"

typedef struct {
    char    *host;
    uint32_t hash;
    uint16_t len;
} bw_slot_t;

static bw_slot_t *bw_table = NULL;
static uint32_t   bw_cap   = 0;
static uint32_t   bw_count = 0;

static inline unsigned char ascii_tolower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + ('a' - 'A')) : c;
}

static inline uint32_t hash_host_lower(const char *s, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)ascii_tolower((unsigned char)s[i]);
        h *= 16777619u;
    }
    return h ? h : 1u;
}

static inline int host_equals_lower(const char *table_host, const char *pkt_host, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)table_host[i] != ascii_tolower((unsigned char)pkt_host[i]))
            return 0;
    }
    return 1;
}

static void bw_rehash(uint32_t new_cap) {
    bw_slot_t *new_tab = calloc(new_cap, sizeof(bw_slot_t));
    if (!new_tab) return;
    uint32_t mask = new_cap - 1u;

    for (uint32_t i = 0; i < bw_cap; i++) {
        if (bw_table[i].host) {
            uint32_t idx = bw_table[i].hash & mask;
            while (new_tab[idx].host) {
                idx = (idx + 1u) & mask;
            }
            new_tab[idx] = bw_table[i];
        }
    }
    free(bw_table);
    bw_table = new_tab;
    bw_cap = new_cap;
}

static int check_get_hostname_slice(const char *host, size_t len, uint32_t h) {
    if (!bw_table) return FALSE;
    uint32_t mask = bw_cap - 1u;
    uint32_t idx = h & mask;
    while (bw_table[idx].host) {
        if (bw_table[idx].hash == h && bw_table[idx].len == len &&
            host_equals_lower(bw_table[idx].host, host, len)) {
            return TRUE;
        }
        idx = (idx + 1u) & mask;
    }
    return FALSE;
}

static int add_hostname(const char *host) {
    if (!host) return FALSE;
    size_t len = strlen(host);
    if (len < 2 || len > HOST_MAXLEN) return FALSE;

    if (bw_cap == 0) {
        bw_rehash(1024u);
    } else if ((bw_count + 1u) * 2u >= bw_cap) {
        bw_rehash(bw_cap * 2u);
    }

    uint32_t h = hash_host_lower(host, len);
    if (check_get_hostname_slice(host, len, h))
        return FALSE;

    char *copy = malloc(len + 1);
    if (!copy) return FALSE;
    for (size_t i = 0; i < len; i++) {
        copy[i] = (char)ascii_tolower((unsigned char)host[i]);
    }
    copy[len] = '\0';

    uint32_t mask = bw_cap - 1u;
    uint32_t idx = h & mask;
    while (bw_table[idx].host) {
        idx = (idx + 1u) & mask;
    }
    bw_table[idx].host = copy;
    bw_table[idx].hash = h;
    bw_table[idx].len  = (uint16_t)len;
    bw_count++;
    return TRUE;
}

int blackwhitelist_load_list(const char *filename) {
    char *line = malloc(HOST_MAXLEN + 1);
    size_t linelen = HOST_MAXLEN + 1;
    int cnt = 0;
    ssize_t read;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        free(line);
        return FALSE;
    }

    while ((read = getline(&line, &linelen, fp)) != -1) {
        line[strcspn(line, "\r\n")] = '\0';
        size_t len = strlen(line);
        if (len > HOST_MAXLEN) {
            printf("WARNING: host %s exceeds maximum host length and has not been added\n", line);
            continue;
        }
        if (len < 2) {
            printf("WARNING: host %s is less than 2 characters, skipping\n", line);
            continue;
        }
        if (add_hostname(line))
            cnt++;
    }
    free(line);
    fclose(fp);
    if (!bw_count) return FALSE;
    printf("Loaded %d hosts from file %s\n", cnt, filename);
    return TRUE;
}

int blackwhitelist_check_hostname(const char *host_addr, size_t host_len) {
    if (UNLIKELY(!bw_table || !host_addr || host_len == 0 || host_len > HOST_MAXLEN))
        return FALSE;

    size_t offset = 0;
    while (offset < host_len) {
        const char *sub = host_addr + offset;
        size_t sub_len = host_len - offset;
        uint32_t h = hash_host_lower(sub, sub_len);
        if (check_get_hostname_slice(sub, sub_len, h))
            return TRUE;

        const void *dot = memchr(sub, '.', sub_len);
        if (!dot) break;
        offset = (size_t)((const char *)dot - host_addr) + 1u;
    }
    return FALSE;
}
