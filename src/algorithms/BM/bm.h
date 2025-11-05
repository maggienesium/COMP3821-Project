#ifndef SRC_ALGORITHMS_BM_BM_H
#define SRC_ALGORITHMS_BM_BM_H

#include <stdint.h>
#include <stdio.h>
#include "../../parse/analytics.h"
#include "../WM/wm.h"

#define NOT_IN_PATTERN -1
/* ---------------------------------------------------------------
 * Struct: BadCharacterTable
 * A lookup table representing the last occurence of each alphabet character in the pattern.
 *  Each table includes:
 *   - character
 *   - final index
 * --------------------------------------------------------------- */

// typedef struct {
//     char character;
//     int position;
// } AlphabetPosition;

// typedef struct {
//     struct AlphabetPosition **blocks;
//     int numBlocks;
//     int numRules;
// } BadCharacterTable;

/**
 * Mapping of a pattern given from a Snort Rule to its corresponding BadCharacter Table
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

#endif 