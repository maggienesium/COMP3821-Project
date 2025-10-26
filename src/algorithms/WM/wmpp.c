/* 
 *                  Wu–Manber Preprocessing
 *
 * ---------------------------------------------------------------
 * Builds shift, hash, and (optional) Bloom filter prefix tables.
 *
 * Reference:
 *   "Efficient Wu–Manber Pattern Matching Hardware for Intrusion 
 *    and Malware Detection" — Monther Aldwairi
 *
 * ---------------------------------------------------------------
 * Preprocessing Overview:
 *
 *   1. Determine the shortest pattern length (m)
 *   2. Select optimal block size (B)
 *   3. Construct shift and hash tables
 *   4. Optionally, initialize Bloom filter
 * ---------------------------------------------------------------
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <math.h>
#include "wm.h"

/* ---------------------------------------------------------------
 *  Dynamically select block size (B) based on dataset heuristics.
 * ---------------------------------------------------------------
 */
int choose_block_size(const PatternSet *ps) {
    if (ps->min_length < 4 || ps->pattern_count > 5000) return 2;
    if (ps->avg_length > 30) return 4;
    return 3;
}

/* ---------------------------------------------------------------
 *   Compute a lightweight FNV-1a hash of the first B bytes of a
 *   pattern for quick mismatch filtering during search.xww
 * ---------------------------------------------------------------
 */
uint32_t hash_prefix(const unsigned char *s, int len, int B) {
    uint32_t h = 0x811C9DC5;
    for (int i = 0; i < (len < B ? len : B); ++i)
        h = (h ^ s[i]) * 0x01000193;
    return h;
}

/* ---------------------------------------------------------------
 *   Convert a sequence of B bytes into a unique numeric key used
 *   for indexing shift and hash tables.
 * ---------------------------------------------------------------
 */
uint32_t block_key(const unsigned char *s, int avail, int B) {
    uint32_t k = 0;
    for (int i = 0; i < B; ++i) {
        unsigned v = (i < avail) ? s[i] : 0;
        k |= ((uint32_t)v) << (8 * i);
    }
    return k;
}

/* ---------------------------------------------------------------
 *   Identify the shortest pattern length (m) for the window size.
 * ---------------------------------------------------------------
 */
void wm_prepare_patterns(PatternSet *ps, int B) {
    if (!ps || ps->pattern_count <= 0) return;

    int m = INT_MAX;
    for (int i = 0; i < ps->pattern_count; ++i) {
        int L = (int)strnlen(ps->patterns[i], MAX_PATTERN_LEN);
        if (L > 0 && L < m) m = L;
    }

    ps->min_length = (m < B) ? B : m;
}

/* ---------------------------------------------------------------
 *   Construct shift and hash tables for the Wu–Manber algorithm,
 *   optionally using a Bloom filter for prefix filtering.
 * ---------------------------------------------------------------
 */
void wm_build_tables(const PatternSet *ps, WuManberTables *tbl, int use_bloom) {
    if (!ps || !tbl) return;

    int B = choose_block_size(ps);
    tbl->B = B;

    int m = (ps->min_length < B) ? B : ps->min_length;
    const uint32_t TABLE_SIZE = (1u << (B * 8));
    int default_shift = m - B + 1;

    tbl->shift_table = wm_calloc(TABLE_SIZE, sizeof(int));
    tbl->hash_table  = wm_calloc(TABLE_SIZE, sizeof(int));
    tbl->next        = wm_calloc((size_t)ps->pattern_count, sizeof(int));
    tbl->prefix_hash = wm_calloc((size_t)ps->pattern_count, sizeof(uint32_t));
    tbl->pat_len     = wm_calloc((size_t)ps->pattern_count, sizeof(int));

    for (uint32_t i = 0; i < TABLE_SIZE; ++i) {
        tbl->shift_table[i] = default_shift;
        tbl->hash_table[i]  = -1;
    }

    if (use_bloom) {
        printf("[*] Using Bloom filter prefix (probabilistic mode).\n");
        bloom_init(&tbl->prefix_filter, ps->pattern_count, 0.01);
    } else {
        printf("[*] Using Hash prefix mode (deterministic mode).\n");
        tbl->prefix_filter.bit_array = NULL;
    }

    for (int pid = 0; pid < ps->pattern_count; ++pid) {
        const unsigned char *P = (const unsigned char *)ps->patterns[pid];
        int L = (int)strlen((const char *)P);

        tbl->pat_len[pid] = L;
        tbl->prefix_hash[pid] = hash_prefix(P, L, B);
        tbl->next[pid] = -1;

        if (use_bloom)
            bloom_add(&tbl->prefix_filter, P, (L < B ? L : B));

        for (int j = 0; j <= m - B; ++j) {
            uint32_t x = block_key(P + j, L - j, B);
            int new_shift = m - j - B;
            if (new_shift < tbl->shift_table[x])
                tbl->shift_table[x] = new_shift;
        }

        uint32_t sfx = block_key(P + (m - B), L - (m - B), B);
        tbl->next[pid] = tbl->hash_table[sfx];
        tbl->hash_table[sfx] = pid;
    }
}

/* ---------------------------------------------------------------
 *   Free all dynamically allocated tables from preprocessing.
 * ---------------------------------------------------------------
 */
void wm_free_tables(WuManberTables *tbl) {
    if (!tbl) return;

    wm_free(tbl->shift_table);
    wm_free(tbl->hash_table);
    wm_free(tbl->next);
    wm_free(tbl->prefix_hash);
    wm_free(tbl->pat_len);

    if (tbl->prefix_filter.bit_array != NULL)
        bloom_free(&tbl->prefix_filter);
}
