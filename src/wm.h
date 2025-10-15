#ifndef WM_H
#define WM_H

#include <stdint.h>

#define B 2                     // Maybe implement an adaptive block size to improve optimisation? i.e. a function that chooses what block size is best depending on input parameters.
#define ALPHABET_SIZE 256       // 256 ASCII character set.
#define MAX_PATTERNS 10000      // Snort and Suricata have around 5 to ten thousand signatures so this is an appropriate upper bound
#define MAX_PATTERN_LEN 128     // Malware patterns rarely exceed 80 so 128 is a safe choice.

typedef struct {
    char patterns[MAX_PATTERNS][MAX_PATTERN_LEN];
    int  pattern_count;
    int  min_len;
} PatternSet;

typedef struct {
    int shift_table[1 << (B * 8)];
    int hash_table[1 << (B * 8)];
    int next[MAX_PATTERNS];
    uint32_t prefix_hash[MAX_PATTERNS];
    int pat_len[MAX_PATTERNS];
} WuManberTables;

uint32_t block_key(const unsigned char *s, int avail);
void wm_prepare_patterns(PatternSet *ps);
void wm_build_tables(const PatternSet *ps, WuManberTables *tbl);
void wm_search(const unsigned char *text, int n, const PatternSet *ps, const WuManberTables *tbl);

#endif
