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
void wm_search(const unsigned char *text, int n,
               const PatternSet *ps, const WuManberTables *tbl)
{
    if (!text || !ps || !tbl || ps->min_len < B) return;

    int m = ps->min_len;
    int pos = m - 1;

    while (pos < n) {
        uint32_t key = block_key(text + pos - B + 1, B);
        int shift = tbl->shift_table[key];

        if (shift > 0) {
            pos += shift;   // No pattern here — skip ahead
        } else {
            // Potential match zone — check all patterns in this bucket
            int pid = tbl->hash_table[key];

            while (pid != -1) {
                int len = tbl->pat_len[pid];

                // Check prefix hash first (cheap)
                uint32_t prefix_h = 0x811C9DC5;
                for (int i = 0; i < (len < B ? len : B); ++i)
                    prefix_h = (prefix_h ^ text[pos - m + 1 + i]) * 0x01000193;

                if (prefix_h == tbl->prefix_hash[pid]) {
                    // Verify full string match
                    int start = pos - m + 1;
                    if (start + len <= n &&
                        strncmp((const char *)text + start,
                                ps->patterns[pid], len) == 0)
                    {
                        printf("[MATCH] Pattern %d ('%s') at position %d\n",
                               pid, ps->patterns[pid], start);
                    }
                }
                pid = tbl->next[pid]; // move through hash bucket chain
            }

            // Advance by one character (can’t skip safely)
            pos += 1;
        }
    }
}