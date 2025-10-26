#ifndef SRC_ALGORITHMS_WM_WM_H_
#define SRC_ALGORITHMS_WM_WM_H_

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------
 *                          Constants
 * --------------------------------------------------------------- */
#define ALPHABET_SIZE    256
#define MAX_PATTERNS     10000
#define MAX_PATTERN_LEN  256

/* ---------------------------------------------------------------
 * BloomFilter:
 *   Probabilistic structure used for prefix filtering in the
 *   Wu–Manber algorithm. Reduces unnecessary hash lookups.
 * --------------------------------------------------------------- */
typedef struct {
    uint8_t  *bit_array;
    uint32_t size;
    uint32_t num_hashes;
} BloomFilter;

/* ---------------------------------------------------------------
 * PatternSet:
 *   Holds all user-provided patterns and computed statistics.
 * --------------------------------------------------------------- */
typedef struct {
    char      patterns[MAX_PATTERNS][MAX_PATTERN_LEN];
    char    **rule_refs;
    int       pattern_count;
    int       min_length;
    int       avg_length;
} PatternSet;

/* ---------------------------------------------------------------
 * WuManberTables:
 *   Stores preprocessed shift and hash tables for Wu–Manber,
 *   along with pattern metadata and optional Bloom filter.
 * --------------------------------------------------------------- */
typedef struct {
    int        B;
    int       *shift_table;
    int       *hash_table;
    int       *next;
    uint32_t  *prefix_hash;
    int       *pat_len;
    BloomFilter prefix_filter;
} WuManberTables;

/* ---------------------------------------------------------------
 * WMGlobalStats:
 *   Tracks global memory analytics for the Wu–Manber algorithm.
 *   Updated automatically by wm_malloc, wm_calloc, wm_realloc,
 *   and wm_free for space complexity measurements.
 * --------------------------------------------------------------- */
typedef struct {
    uint64_t alloc_count;
    uint64_t free_count;
    uint64_t total_bytes;
} WMGlobalStats;

/* Global analytics reference (defined in main.c) */
extern WMGlobalStats *g_wm_global_stats;

/* ---------------------------------------------------------------
 *          Wu–Manber Preprocessing and Search API
 * --------------------------------------------------------------- */
uint32_t block_key(const unsigned char *s, int avail, int B);
uint32_t hash_prefix(const unsigned char *s, int len, int B);

int choose_block_size(const PatternSet *ps);
void wm_prepare_patterns(PatternSet *ps, int B);
void wm_build_tables(const PatternSet *ps, WuManberTables *tbl, int use_bloom);
void wm_free_tables(WuManberTables *tbl);

void wm_search(const unsigned char *text, int n,
               const PatternSet *ps, const WuManberTables *tbl);

/* ---------------------------------------------------------------
 *                      Bloom Filter API
 * --------------------------------------------------------------- */
void bloom_init(BloomFilter *bf, int n, double p);
void bloom_add(BloomFilter *bf, const unsigned char *data, int len);
int  bloom_check(const BloomFilter *bf, const unsigned char *data, int len);
void bloom_free(BloomFilter *bf);

/* ---------------------------------------------------------------
 *              Memory Tracking Wrappers (Analytics)
 * --------------------------------------------------------------- */
void *wm_malloc(size_t size);
void *wm_realloc(void *ptr, size_t size);
void *wm_calloc(size_t count, size_t size);
void  wm_free(void *ptr);

#endif  // SRC_ALGORITHMS_WM_WM_H_
