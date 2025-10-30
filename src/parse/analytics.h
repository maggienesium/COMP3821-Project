// NOLINTBEGIN
#ifndef SRC_PARSE_ANALYTICS_H_
#define SRC_PARSE_ANALYTICS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 *   Generic performance analytics shared across all algorithms
 * --------------------------------------------------------------- */
typedef struct {
    const char *algorithm_name;

    // Common metrics
    uint64_t chars_scanned;
    uint64_t comparisons;
    uint64_t transitions;
    uint64_t fail_steps;
    uint64_t shifts;
    uint64_t matches;

    // Wu–Manber specific metrics
    uint64_t windows;
    uint64_t sum_shift;
    uint64_t hash_hits;
    uint64_t bloom_checks;
    uint64_t bloom_pass;
    uint64_t chain_steps;
    uint64_t exact_matches;
    uint64_t verif_after_bloom;

    // Timing & throughput
    double   elapsed_sec;
    double   throughput_mb_s;
    uint64_t file_size;
} AlgorithmStats;

/* ---------------------------------------------------------------
 *                    Memory tracking stats
 * --------------------------------------------------------------- */
typedef struct {
    uint64_t alloc_count;
    uint64_t free_count;
    size_t   total_bytes;
} MemoryStats;

extern MemoryStats *global_mem_stats;

/* ---------------------------------------------------------------
 *              Find current throughput for algorithm
 * --------------------------------------------------------------- */
static inline void compute_throughput(AlgorithmStats *s) {
    if (!s) return;
    if (s->elapsed_sec > 0) {
        s->throughput_mb_s = ((double)s->file_size / (1024.0 * 1024.0)) / s->elapsed_sec;
    } else {
        s->throughput_mb_s = 0.0;
    }
}

/* ---------------------------------------------------------------
 *                 Print runtime algorithm stats
 * --------------------------------------------------------------- */
static inline void print_algorithm_stats(const AlgorithmStats *s) {
    if (!s) return;

    printf("\n[Performance Analytics: %s]\n",
           s->algorithm_name ? s->algorithm_name : "Unknown");

    // Common metrics
    if (s->chars_scanned) printf("  Characters scanned     : %'lu\n",
        (unsigned long)s->chars_scanned);
    if (s->comparisons)   printf("  Comparisons            : %'lu\n",
        (unsigned long)s->comparisons);
    if (s->transitions)   printf("  State transitions      : %'lu\n",
        (unsigned long)s->transitions);
    if (s->fail_steps)    printf("  Fail traversals        : %'lu\n",
        (unsigned long)s->fail_steps);
    if (s->shifts)        printf("  Shifts                 : %'lu\n",
        (unsigned long)s->shifts);
    if (s->matches)       printf("  Matches (total)        : %'lu\n",
        (unsigned long)s->matches);

    // Wu–Manber specific metrics
    if (s->windows)       printf("  Windows processed      : %'lu\n",
        (unsigned long)s->windows);
    if (s->sum_shift)     printf("  Total shift distance   : %'lu\n",
        (unsigned long)s->sum_shift);
    if (s->hash_hits)     printf("  Hash table hits        : %'lu\n",
        (unsigned long)s->hash_hits);
    if (s->bloom_checks)  printf("  Bloom checks           : %'lu\n",
        (unsigned long)s->bloom_checks);
    if (s->bloom_pass)    printf("  Bloom positive checks  : %'lu\n",
        (unsigned long)s->bloom_pass);
    if (s->chain_steps)   printf("  Chain traversal steps  : %'lu\n",
        (unsigned long)s->chain_steps);
    if (s->exact_matches) printf("  Exact string matches   : %'lu\n",
        (unsigned long)s->exact_matches);
    if (s->verif_after_bloom)
                          printf("  Verified post-Bloom    : %'lu\n",
                            (unsigned long)s->verif_after_bloom);

    // Derived metrics — ratios and averages
    if (s->windows > 0) {
        double avg_shift = (double)s->sum_shift / (double)s->windows;
        printf("\n  ➤ Average shift length : %.2f\n", avg_shift);

        if (s->hash_hits)
            printf("  ➤ Avg. chain steps / hit: %.2f\n",
                   (double)s->chain_steps / (double)s->hash_hits);

        if (s->bloom_checks)
            printf("  ➤ Bloom pass rate      : %.2f%%\n",
                   (100.0 * (double)s->bloom_pass) / (double)s->bloom_checks);

        printf("  ➤ Match rate (per window): %.4f%%\n",
               (100.0 * (double)s->exact_matches) / (double)s->windows);
    }

    // Timing & throughput
    printf("\n  Elapsed time           : %.6f sec\n", s->elapsed_sec);
    printf("  Throughput             : %.2f MB/s\n", s->throughput_mb_s);
}

/* ---------------------------------------------------------------
 *                 Print memory usage stats
 * --------------------------------------------------------------- */
static inline void print_memory_stats(const char *label, const MemoryStats *m) {
    if (!m) return;

    printf("\n[Space Complexity Summary: %s]\n", label ? label : "Unknown");
    printf("  Total allocations : %lu\n",
        (unsigned long)m->alloc_count);
    printf("  Total frees       : %lu\n",
        (unsigned long)m->free_count);
    printf("  Total bytes used  : %zu bytes (%.2f MB)\n",
           m->total_bytes, (double)m->total_bytes / (1024.0 * 1024.0));
}

void *track_malloc(size_t size);
void *track_calloc(size_t count, size_t size);
void *track_realloc(void *ptr, size_t size);
void  track_free(void *ptr);

#endif  // SRC_PARSE_ANALYTICS_H_
// NOLINTEND