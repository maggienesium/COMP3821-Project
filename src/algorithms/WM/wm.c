/* 
 *                  Wu–Manber Multi-Pattern Matcher
 *
 * ---------------------------------------------------------------
 * Implements the search phase of the Wu–Manber algorithm for
 * multiple pattern matching.
 *
 * Reference:
 *   "Efficient Wu-Manber Pattern Matching Hardware for Intrusion 
 *    and Malware Detection" — Monther Aldwairi
 *
 * Core Idea:
 *   Use precomputed shift and hash tables (see wmpp.c and wm.h)
 *   to skip ahead in the input efficiently, minimizing unnecessary
 *   comparisons. Can optionally integrate Bloom filters for
 *   probabilistic prefix filtering.
 *
 *   Text window size = m (length of shortest pattern)
 *   Block size       = B 
 * --------------------------------------------------------------- */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include "wm.h"
#include "../../parse/analytics.h"


/* ---------------------------------------------------------------
 *   Perform Wu–Manber multi-pattern search and print performance
 *   and memory analytics.
 * --------------------------------------------------------------- */
void wm_search(const unsigned char *text, int n,
               const PatternSet *ps, const WuManberTables *tbl) {
    if (!text || !ps || !tbl) return;

    AlgorithmStats s = {0};
    s.algorithm_name = "Wu–Manber (Deterministic)";
    s.file_size = (uint64_t)n;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int B = tbl->B;
    int m = ps->min_length;
    if (m < B) m = B;
    const BloomFilter *bf = &tbl->prefix_filter;
    int use_bloom = (bf->bit_array != NULL);

    for (int i = m - 1; i < n; ) {
        s.windows++;

        uint32_t key = block_key(text + i - B + 1, B, B);
        int shift = tbl->shift_table[key];
        s.sum_shift += (uint64_t)shift;

        if (shift > 0) {
            i += shift;
            continue;
        }

        s.hash_hits++;

        if (use_bloom) {
            s.bloom_checks++;
            if (!bloom_check(bf, text + i - m + 1, B)) {
                i++;
                continue;
            }
            s.bloom_pass++;
        }

        uint32_t h = hash_prefix(text + i - m + 1, m, B);
        for (int pid = tbl->hash_table[key]; pid != -1; pid = tbl->next[pid]) {
            s.chain_steps++;
            if (tbl->prefix_hash[pid] == h &&
                strncmp((const char *)text + i - m + 1,
                        ps->patterns[pid],
                        (size_t)ps->min_length) == 0) {
                s.exact_matches++;
                s.verif_after_bloom++;
            }
        }
        i++;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    s.elapsed_sec = ((end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec)) / 1e9;

    compute_throughput(&s);
    print_algorithm_stats(&s);
}
