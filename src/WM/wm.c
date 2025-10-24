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
#include <time.h>
#include "wm.h"

/* ---------------------------------------------------------------
 * Struct: WMStats
 * 
 * Tracks runtime analytics such as:
 *      - Total windows examined
 *      - Hash lookups
 *      - Bloom filter checks
 *      - Total elapsed time.
 * ---------------------------------------------------------------
 */
typedef struct {
    uint64_t windows;
    uint64_t sum_shift;
    uint64_t hash_hits;
    uint64_t chain_steps;
    uint64_t exact_matches;
    uint64_t bloom_checks;
    uint64_t bloom_pass;
    uint64_t verif_after_bloom;
    double   elapsed_sec;
} WMStats;

/* ---------------------------------------------------------------
 * Purpose:
 *   Print aggregated performance statistics from a single
 *   Wu–Manber search run.
 *
 * Parameters:
 *   s          - pointer to WMStats struct with counters
 *   use_bloom  - flag (1 if Bloom filter mode enabled)
 *   n          - number of bytes scanned (for throughput)
 * ---------------------------------------------------------------
 */
static void wm_print_analytics(const WMStats *s, int use_bloom, int n, int B) {
    printf("\n[Search Stats]\n");
    printf("  Windows examined     : %llu\n", (uint64_t)s->windows);
    printf("  Block size (B)       : %d\n", B);
    printf("  Avg shift distance   : %.3f\n",
           s->windows ? (double)s->sum_shift / s->windows : 0.0);
    printf("  Hash hits            : %llu\n", (uint64_t)s->hash_hits);
    printf("  Chain traversals     : %llu\n", (uint64_t)s->chain_steps);
    printf("  Exact matches        : %llu\n", (uint64_t)s->exact_matches);

    if (use_bloom) {
        printf("  Bloom checks         : %llu\n", (uint64_t)s->bloom_checks);
        printf("  Bloom positives      : %llu\n", (uint64_t)s->bloom_pass);
        printf("  Verified after Bloom : %llu\n", (uint64_t)s->verif_after_bloom);
    }

    printf("  Elapsed time         : %.6f sec\n", s->elapsed_sec);
    printf("  Throughput           : %.2f MB/s\n",
           s->elapsed_sec > 0 ? (n / (1024.0 * 1024.0)) / s->elapsed_sec : 0.0);
}

/* ---------------------------------------------------------------
 * Purpose:
 *   Perform the Wu–Manber search on a given text buffer, printing
 *   any matching patterns and detailed analytics.
 *
 * Parameters:
 *   text   - pointer to input buffer
 *   n      - size of buffer (in bytes)
 *   ps     - pointer to pattern set
 *   tbl    - pointer to precomputed WuManberTables
 * ---------------------------------------------------------------
 */
void wm_search(const unsigned char *text, int n, const PatternSet *ps, const WuManberTables *tbl) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    WMStats s = {0};

    int B = tbl->B;
    int m = ps->min_length;
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
                strncmp((const char *)text + i - m + 1, ps->patterns[pid],
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

    wm_print_analytics(&s, use_bloom, n, tbl->B);
}
