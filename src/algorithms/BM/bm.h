#ifndef SRC_ALGORITHMS_BM_BM_H
#define SRC_ALGORITHMS_BM_BM_H

#include <stdint.h>
#include <stdio.h>
#include "../../parse/analytics.h"
#include "../WM/wm.h"

#define NOT_IN_PATTERN -1
/**
 * Mapping of a pattern given from a Snort Rule to its corresponding
 * BadCharacter, Good Suffix shift table and the border table where a border is
 * defined as a prefix text suffix trio where the prefix and suffix are equal.
 */
typedef struct {
    char *pattern;
    int pattern_length;
    int badCharTable[ALPHABET_SIZE];
    int goodSuffixTable[ALPHABET_SIZE];
    int *borderTable;
} PatternTable;

/**
 * Struct storing all the patterns and their pre-processing tables
 */
typedef struct {
    PatternTable *patterns;
    int num_patterns;
} BMPatterns;

/* ---------------------------------------------------------------
 *                      Function Prototypes
 * --------------------------------------------------------------- */
BMPatterns *bm_preprocessing(PatternSet *ps);

void bm_search(BMPatterns *bm, const char *text, size_t text_len);

void bm_free_tables(BMPatterns *bm);

#endif 