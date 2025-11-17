#ifndef SRC_ALGORITHMS_SH_SH_H_
#define SRC_ALGORITHMS_SH_SH_H_

#include <stdint.h>
#include <stdio.h>
#include "../../parse/analytics.h"
/* ---------------------------------------------------------------
 *                          Constants
 * --------------------------------------------------------------- */
#define MAX_CHAR           256
#define MAX_FILE_SIZE      10485760   /* 10 MB */
#define MAX_PATTERN_SIZE   256
#define MAX_PATTERNS       10000
#define MAX_LINE_LENGTH    4096

/* ---------------------------------------------------------------
 * Struct: PatternList
 *  Stores indices of patterns that have a specific character
 *  at the rightmost position of the minimum length window
 * --------------------------------------------------------------- */
typedef struct {
    int *indices;      // Array of pattern indices
    int count;         // Number of patterns in this list
    int capacity;      // Allocated capacity
} PatternList;

/* ---------------------------------------------------------------
 * Struct: Pattern
 *  Represents a single parsed Snort rule pattern.
 *  Each pattern includes:
 *   - Raw pattern string (may include hex-encoded bytes)
 *   - Rule metadata (sid, message, nocase flag)
 * --------------------------------------------------------------- */
typedef struct {
    char *pattern;
    int   length;
    int   id;
    char *msg;
    int   sid;
    int   nocase;
} Pattern;

/* ---------------------------------------------------------------
 *                      Function Prototypes
 * --------------------------------------------------------------- */
void setHorspoolSearch(const char *text, uint64_t textLength,
                       Pattern *patterns, int numPatterns,
                       int *shiftTable, int minLength,
                       PatternList *hashTable,
                       AlgorithmStats *s);
void performSetHorspool(const char *text, uint64_t textLength,
                        Pattern *patterns, int numPatterns);
void buildSetHorspoolShiftTable(Pattern *patterns, int numPatterns, int *shiftTable);
void buildPatternHashTable(Pattern *patterns, int numPatterns, int minLength, PatternList *hashTable);
void freePatternHashTable(PatternList *hashTable);
int compareChar(char a, char b, int nocase);

#endif  // SRC_ALGORITHMS_SH_SH_H_
