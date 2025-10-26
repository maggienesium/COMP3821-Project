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
 * ---------------------------------------------------------------
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include "wm.h"

/* ---------------------------------------------------------------
 * Struct: WMStats
 *  Tracks runtime analytics for a single Wu–Manber search run:
 *    - Total windows examined
 *    - Shift operations and hash lookups
 *    - Bloom filter checks (if enabled)
 *    - Dynamic memory activity (for space complexity)
 *    - Elapsed time
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
    uint64_t alloc_count;       // malloc/realloc count
    uint64_t free_count;        // free count
    size_t   total_bytes;       // total bytes allocated
    double   elapsed_sec;
} WMStats;

/* Local analytics tracker reference */
static WMStats *local_wm_stats = NULL;

/* ---------------------------------------------------------------
 *   Memory wrappers to instrument allocation activity.
 *   Enables estimation of space complexity over runtime.
 * ---------------------------------------------------------------
 */
void *wm_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr && g_wm_global_stats) {
        g_wm_global_stats->alloc_count++;
        g_wm_global_stats->total_bytes += size;
    }
    return ptr;
}

void *wm_calloc(size_t count, size_t size) {
    void *ptr = calloc(count, size);
    if (ptr && g_wm_global_stats) {
        g_wm_global_stats->alloc_count++;
        g_wm_global_stats->total_bytes += count * size;
    }
    return ptr;
}

void *wm_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (new_ptr && g_wm_global_stats) {
        g_wm_global_stats->alloc_count++;
        g_wm_global_stats->total_bytes += size;
    }
    return new_ptr;
}

void wm_free(void *ptr) {
    if (ptr && g_wm_global_stats) g_wm_global_stats->free_count++;
    free(ptr);
}

/* ---------------------------------------------------------------
 *   Print aggregated performance and memory statistics for a
 *   Wu–Manber pattern search.
 * ---------------------------------------------------------------
 */
static void wm_print_analytics(const WMStats *s, int use_bloom, int n, int B) {
    printf("\n[Search Stats: Wu–Manber]\n");
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

    printf("\n[Memory Usage]\n");
    if (g_wm_global_stats) {
        printf("  Allocations          : %llu\n",
            (uint64_t)g_wm_global_stats->alloc_count);
        printf("  Frees                : %llu\n",
            (uint64_t)g_wm_global_stats->free_count);
        printf("  Total bytes alloc’d  : %llu bytes\n",
            (uint64_t)g_wm_global_stats->total_bytes);
    } else {
        printf("  (no global memory tracker attached)\n");
    }

    printf("\n[Performance]\n");
    printf("  Elapsed time         : %.6f sec\n", s->elapsed_sec);
    printf("  Throughput           : %.2f MB/s\n",
           s->elapsed_sec > 0 ? (n / (1024.0 * 1024.0)) / s->elapsed_sec : 0.0);
}

/* ---------------------------------------------------------------
 *   Perform Wu–Manber multi-pattern search and print performance
 *   and memory analytics.
 * ---------------------------------------------------------------
 */
void wm_search(const unsigned char *text, int n,
               const PatternSet *ps, const WuManberTables *tbl) {
    if (!text || !ps || !tbl) return;

    WMStats s = {0};
    local_wm_stats = &s;

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

    wm_print_analytics(&s, use_bloom, n, tbl->B);
    local_wm_stats = NULL;
}
