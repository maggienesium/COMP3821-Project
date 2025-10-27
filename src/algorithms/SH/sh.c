/*
 *               Set Horspool Multi-Pattern Matcher
 * ----------------------------------------------------------------
 * Implements the Set Horspool algorithm for multi-pattern matching
 * using preloaded Snort-style rules.
 *
 * Reference:
 *   - "Set Horspool algorithm for intrusion detection systems"
 *     (adapted from Wu–Manber-style optimizations)
 * ----------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "sh.h"
#include "../../parse/analytics.h"
/* ---------------------------------------------------------------
 *                   Internal Global Counters
 * --------------------------------------------------------------- */
static int totalComparisons = 0;
static int totalOccurrences = 0;
static int patternMatches[MAX_PATTERNS] = {0};

/* ---------------------------------------------------------------
 *                 Search Phase (core algorithm)
 * --------------------------------------------------------------- */
void setHorspoolSearch(const char *text, uint64_t textLength,
                       Pattern *patterns, int numPatterns,
                       int *shiftTable, int minLength,
                       AlgorithmStats *s) {
    if (minLength <= 0 || !text || !patterns) return;

    uint64_t pos = 0;
    while (pos + (uint64_t)minLength <= textLength) {
        uint64_t windowEnd = pos + (uint64_t)minLength - 1;
        if (windowEnd >= textLength) break;

        int foundMatch = 0;
        int maxShift = shiftTable[(unsigned char)text[windowEnd]];

        for (int p = 0; p < numPatterns; p++) {
            int patternLen = patterns[p].length;
            if (patternLen <= 0 || pos + (uint64_t)patternLen > textLength)
                continue;

            int matched = 1;
            for (int j = patternLen - 1; j >= 0; j--) {
                totalComparisons++;
                if (!compareChar(text[pos + (uint64_t)j],
                                 patterns[p].pattern[j],
                                 patterns[p].nocase)) {
                    matched = 0;
                    break;
                }
            }

            if (matched) {
                totalOccurrences++;
                patternMatches[p]++;
                s->matches++;
                foundMatch = 1;
            }
        }

        if (foundMatch)
            pos++;
        else
            pos += (uint64_t)maxShift;

        s->chars_scanned++;
        s->shifts += (uint64_t)maxShift;
    }
}


/* ---------------------------------------------------------------
 *                          Public API
 * --------------------------------------------------------------- */
void performSetHorspool(const char *text, uint64_t textLength,
                        Pattern *patterns, int numPatterns) {
    AlgorithmStats s = {0};
    s.algorithm_name = "Set–Horspool";
    s.file_size = textLength;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int minLength = patterns[0].length;
    for (int i = 1; i < numPatterns; i++) {
        if (patterns[i].length < minLength)
            minLength = patterns[i].length;
    }

    int *shiftTable = (int *)track_malloc(MAX_CHAR * sizeof(int));
    buildSetHorspoolShiftTable(patterns, numPatterns, shiftTable);

    setHorspoolSearch(text, textLength, patterns, numPatterns, shiftTable, minLength, &s);

    clock_gettime(CLOCK_MONOTONIC, &end);
    s.elapsed_sec = ((end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec)) / 1e9;

    /* To ensure that throughput values remain physically meaningful and comparable across runs, 
     * I applied a lower bound of 1 ms (0.001 s) to measured elapsed times. This prevents the 
     * division by near-zero durations that would otherwise yield inflated throughput figures 
     * while maintaining the correct order of magnitude for genuinely fast scans. */
    if (s.elapsed_sec < 1e-3)
        s.elapsed_sec = 1e-3;

    compute_throughput(&s);
    print_algorithm_stats(&s);
    track_free(shiftTable);
}

/* ---------------------------------------------------------------
 *                 Utility: Build Shift Table
 * --------------------------------------------------------------- */
void buildSetHorspoolShiftTable(Pattern *patterns, int numPatterns, int *shiftTable) {
    int minLength = patterns[0].length;
    for (int i = 1; i < numPatterns; i++) {
        if (patterns[i].length < minLength)
            minLength = patterns[i].length;
    }

    for (int i = 0; i < MAX_CHAR; i++) {
        shiftTable[i] = minLength;
    }

    for (int p = 0; p < numPatterns; p++) {
        for (int i = 0; i < minLength - 1; i++) {
            unsigned char ch = (unsigned char)patterns[p].pattern[i];
            int shift = minLength - 1 - i;
            if (shift < shiftTable[ch]) shiftTable[ch] = shift;

            if (patterns[p].nocase && isalpha((unsigned char)ch)) {
                unsigned char alt = (unsigned char)(isupper((unsigned char)ch)
                                    ? tolower((unsigned char)ch)
                                    : toupper((unsigned char)ch));
                if (shift < shiftTable[alt]) shiftTable[alt] = shift;
            }
        }
    }
}

/* ---------------------------------------------------------------
 *              Utility: Case-Insensitive Comparison
 * --------------------------------------------------------------- */
int compareChar(char a, char b, int nocase) {
    return nocase
        ? (tolower((unsigned char)a) == tolower((unsigned char)b))
        : (a == b);
}
