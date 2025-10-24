#ifndef SRC_WM_WM_H_
#define SRC_WM_WM_H_

#include <stdint.h>

#define ALPHABET_SIZE 256       // 256 ASCII character set.
#define MAX_PATTERNS 10000
#define MAX_PATTERN_LEN 256

typedef struct {
    uint8_t *bit_array;
    uint32_t size;
    uint32_t num_hashes;
} BloomFilter;

typedef struct {
    char patterns[MAX_PATTERNS][MAX_PATTERN_LEN];
    char **rule_refs;
    int pattern_count;
    int min_length;
    int avg_length;
} PatternSet;

typedef struct {
    int B;
    int *shift_table;
    int *hash_table;
    int *next;
    uint32_t *prefix_hash;
    int *pat_len;
    BloomFilter prefix_filter;
} WuManberTables;

uint32_t block_key(const unsigned char *s, int avail, int B);
uint32_t hash_prefix(const unsigned char *s, int len, int B);
void wm_prepare_patterns(PatternSet *ps, int B);
void wm_build_tables(const PatternSet *ps, WuManberTables *tbl, int use_bloom);
void wm_free_tables(WuManberTables *tbl);
void wm_search(const unsigned char *text, int n, const PatternSet *ps, const WuManberTables *tbl);
void bloom_init(BloomFilter *bf, int n, double p);
void bloom_add(BloomFilter *bf, const unsigned char *data, int len);
int bloom_check(const BloomFilter *bf, const unsigned char *data, int len);
void bloom_free(BloomFilter *bf);

#endif  // SRC_WM_WM_H_
