/* 
 *                  Wu-Manber Pattern Searching
 *
 * ---------------------------------------------------------------
 * Implements the search phase of the Wu–Manber algorithm.
 *
 * Reference:
 *   "Efficient Wu-Manber Pattern Matching Hardware for Intrusion 
 *    and Malware Detection" - Monther Aldwairi
 *
 * Core Idea:
 *   Use precomputed shift and hash tables (see wmpp.c and wm.h)
 *   to skip ahead in the input text efficiently, reducing 
 *   unnecessary comparisons.
 *
 *   Text window size = m (length of shortest pattern)
 *   Block size       = B 
 *
 * ---------------------------------------------------------------
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "wm.h"

/*
 * ---------------------------------------------------------------
 * Purpose: Search for matching patterns
 * 
 * 
 * Parameters:
 *   text     - pointer to the text buffer to scan
 *   n        - length of text
 *   ps       - pointer to pattern set
 *   tbl      - pointer to precomputed WuManberTables
 *
 * Output:
 *   Prints matching pattern IDs and positions to stdout.
 * ---------------------------------------------------------------
 */
void wm_search(const unsigned char *text, int n, const PatternSet *ps, const WuManberTables *tbl) {
    
    int B = tbl->B;
    int m = ps->min_length;
    const BloomFilter *bf = &tbl->prefix_filter;
    int use_bloom = (bf->bit_array != NULL);

    for (int i = m - 1; i < n; ) {
        uint32_t key = block_key(text + i - B + 1, B, B);
        int shift = tbl->shift_table[key];

        if (shift > 0) {
            i += shift;
        } else {
            if (use_bloom) {
                if (!bloom_check(bf, text + i - m + 1, B)) {
                    i++;
                    continue;
                }
            }

            uint32_t h = hash_prefix(text + i - m + 1, m, B);

            for (int pid = tbl->hash_table[key]; pid != -1; pid = tbl->next[pid]) {
                if (tbl->prefix_hash[pid] == h &&
                    strncmp((const char *)text + i - m + 1, ps->patterns[pid], (size_t) ps->min_length) == 0) {
                    printf("Match found: %s at %d\n", ps->patterns[pid], i - m + 1);
                }
            }
            i++;
        }
    }
}