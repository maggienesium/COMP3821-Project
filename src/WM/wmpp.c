/* 
 *                  Wu-Manber Preprocessing
 *
 * ---------------------------------------------------------------
 * Builds Shift and Hash tables and (optional) prefix hashes.
 *
 * Reference:
 *   "Efficient Wu-Manber Pattern Matching Hardware for Intrusion 
 *    and Malware Detection" - Monther Aldwairi
 *
 * ---------------------------------------------------------------
 * Preprocessing Overview:
 *
 *   1. Determine the size of the matching window (m),
 *      which is the length of the shortest pattern.
 *   2. Construct the shift and hash tables.
 *
 * The shift table stores the default forward distance for a block
 * of characters (size B).
 * 
 * If a block doesn’t appear in any pattern:
 *      Shift[x] = m - B + 1
 * Otherwise (if the block exists in some pattern):
 *      Shift[x] = m - q
 * where q is the rightmost place x occurred in any of the
 * patterns. If the shift for a block is zero then all patterns 
 * containing x are inserted as a linked list in the hash table.
 *
 * The hash table maps the B-byte suffix of each pattern’s m-length
 * prefix to a linked list of pattern indices that share that suffix.
 *
 * ---------------------------------------------------------------
 * Example (for B=2):
 *   P = {"MALWARE", "EVIL", "BAD"}
 *   m = 3  (shortest pattern)
 *
 *   Shift[x] and Hash[x] are filled accordingly.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include "wm.h"

/* ---------------------------------------------------------------
 * Purpose:
 *   Adaptive Block Size choice:
 *      if pattern length < 4, B = 2
 *      if avg_pattern_length > 20, B = 3
 *      if pattern_count > 5000, B = 2
 *
 * Parameters:
 *   s   - pointer to pattern
 *   len - pattern length
 *
 * Returns:
 *   32-bit hash of the first min(B, len) bytes.
 * 
 * Credit: https://ssojet.com/hashing/fnv-1a-in-python/
 * --------------------------------------------------------------- */
static int choose_block_size(const PatternSet *ps) {
    if (ps->min_length < 4 || ps->pattern_count > 5000) return 2;
    if (ps->avg_length > 30) return 4;
    return 3;
}

/* ---------------------------------------------------------------
 * Helper: Compute a simple prefix hash for quick verification.
 *
 * Purpose:
 *   Computes a small hash (using FNV-1a) of the first B bytes of
 *   a pattern to quickly reject mismatches during search.
 *
 * Parameters:
 *   s   - pointer to pattern
 *   len - pattern length
 *
 * Returns:
 *   32-bit hash of the first min(B, len) bytes.
 * 
 * Credit: https://ssojet.com/hashing/fnv-1a-in-python/
 * --------------------------------------------------------------- */
uint32_t hash_prefix(const unsigned char *s, int len, int B) {
    uint32_t h = 0x811C9DC5;    // (FNV offset basis)
    for (int i = 0; i < (len < B ? len : B); ++i)
        h = (h ^ s[i]) * 0x01000193;    // (FNV prime)
    return h;
}

/* ---------------------------------------------------------------
 * Helper: Compute a numeric key for a B-byte block.
 *
 * Purpose:
 *   Converts a sequence of up to B bytes into a unique integer key,
 *   used as an index into the shift and hash tables.
 *
 * e.g. 2 and 3 are the two recommended values for block size.
 *     B=2:  "AB"  → 65 + (66 << 8) = 16961
 *     B=3:  "ABC" → 65 + (66 << 8) + (67 << 16) = 4407873
 *
 * Parameters:
 *   s      - pointer to the start of the character block
 *   avail  - number of bytes remaining in s (may be less than B)
 *
 * Returns:
 *   A 32-bit integer representing the packed key.
 * --------------------------------------------------------------- */
uint32_t block_key(const unsigned char *s, int avail, int B) {
    uint32_t k = 0;
    for (int i = 0; i < B; ++i) {
        unsigned v = (i < avail) ? s[i] : 0;    // pad with zeros if short
        k |= ((uint32_t)v) << (8 * i);          // little-endian format
    }
    return k;
}

/* ---------------------------------------------------------------
 * Step 1: Determine the matching window size (m).
 *
 * Purpose:
 *   Finds the length of the shortest pattern in the pattern set.
 *   Wu–Manber uses this as the size of the matching window.
 *
 * Parameters:
 *   ps - Pointer to PatternSet containing all patterns.
 *
 * Output:
 *   Updates ps->min_len with the shortest pattern length.
 *   If fewer than B characters, min_len is set to B.
 * --------------------------------------------------------------- */
void wm_prepare_patterns(PatternSet *ps, int B) {
    if (!ps || ps->pattern_count <= 0)  // no valid patterns
        return;

    int m = INT_MAX;

    for (int i = 0; i < ps->pattern_count; ++i) {
        int L = (int)strnlen(ps->patterns[i], MAX_PATTERN_LEN);
        if (L > 0 && L < m)
            m = L;
    }

    if (m < B)
        m = B;

    ps->min_length = m;
}

/* ---------------------------------------------------------------
 * Step 2: Build Shift and Hash Tables
 *
 * Purpose:
 *   Constructs the shift and hash tables and prefix hashes based 
 *   on the pattern set and block size B.
 *
 * Parameters:
 *   ps  - Pointer to the preprocessed pattern set
 *   tbl - Pointer to WuManberTables to populate
 *
 * Notes:
 *   - Shift table entries start at default value (m - B + 1)
 *   - Shift[x] is reduced if block x occurs within any pattern
 *   - Hash table stores indices of patterns sharing same B-suffix
 * --------------------------------------------------------------- */
void wm_build_tables(const PatternSet *ps, WuManberTables *tbl, int use_bloom) {
    if (!ps || !tbl)
        return;

    int B = choose_block_size(ps);
    tbl->B = B;

    int m = ps->min_length;
    if (m < B)
        m = B;

    const uint32_t TABLE_SIZE = (1u << (B * 8));
    int default_shift = m - B + 1;

    tbl->shift_table = calloc(TABLE_SIZE, sizeof(int));
    tbl->hash_table  = calloc(TABLE_SIZE, sizeof(int));
    tbl->next        = calloc((size_t) ps->pattern_count, sizeof(int));
    tbl->prefix_hash = calloc((size_t) ps->pattern_count, sizeof(uint32_t));
    tbl->pat_len     = calloc((size_t) ps->pattern_count, sizeof(int));

    for (uint32_t i = 0; i < TABLE_SIZE; ++i) {
        tbl->shift_table[i] = default_shift;
        tbl->hash_table[i]  = -1;
    }

    if (use_bloom) {
        printf("[*] Using Bloom filter prefix (Probabilistic).\n");
        bloom_init(&tbl->prefix_filter, ps->pattern_count, 0.01);   // Set a 1% false positive rate
    } else {
        printf("[*] Using Hash prefix mode (Deterministic).\n");
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
 * Step 3: Clear any used memory
 *
 * Purpose:
 *   No one wants a memory leak...
 *
 * Parameters:
 *   tbl - Pointer to WuManberTables to clear
 *
 * Notes:
 *   - Calls bloom_free if it was used in the tbl struct.
 * --------------------------------------------------------------- */
void wm_free_tables(WuManberTables *tbl) {
    if (!tbl) return;

    free(tbl->shift_table);
    free(tbl->hash_table);
    free(tbl->next);
    free(tbl->prefix_hash);
    free(tbl->pat_len);

    if (tbl->prefix_filter.bit_array != NULL)
        bloom_free(&tbl->prefix_filter);
}
