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
 *                 Search Phase (core algorithm)
 * --------------------------------------------------------------- */
void setHorspoolSearch(const char *text, uint64_t textLength,
                       Pattern *patterns, int numPatterns __attribute__((unused)),
                       int *shiftTable, int minLength,
                       PatternList *hashTable,
                       AlgorithmStats *s) {
    if (minLength <= 0 || !text || !patterns) return;

    uint64_t pos = 0;
    while (pos + (uint64_t)minLength <= textLength) {
        uint64_t windowEnd = pos + (uint64_t)minLength - 1;
        if (windowEnd >= textLength) break;

        s->windows++;
        unsigned char endChar = (unsigned char)text[windowEnd];
        int shift = shiftTable[endChar];

        // OPTIMIZATION: Only check patterns when shift is minimal
        // If shift > 1, we can skip this position entirely
        if (shift > 1) {
            pos += (uint64_t)shift;
            s->sum_shift += (uint64_t)shift;
            continue;
        }

        // shift == 0 or 1: Check only patterns in the hash table for this character
        PatternList *candidateList = &hashTable[endChar];
        int foundMatch = 0;

        for (int i = 0; i < candidateList->count; i++) {
            int p = candidateList->indices[i];
            int patternLen = patterns[p].length;

            if (patternLen <= 0 || pos + (uint64_t)patternLen > textLength)
                continue;

            // Verify full pattern match
            int matched = 1;
            for (int j = 0; j < patternLen; j++) {
                s->comparisons++;
                if (!compareChar(text[pos + (uint64_t)j],
                                 patterns[p].pattern[j],
                                 patterns[p].nocase)) {
                    matched = 0;
                    break;
                }
            }

            if (matched) {
                s->matches++;
                foundMatch = 1;
                // Don't break - continue checking other patterns
                // (overlapping matches are valid)
            }
        }

        // Use shift table for next position
        if (foundMatch) {
            pos++;  // Shift by 1 to find overlapping matches
        } else {
            pos += (shift > 0) ? (uint64_t)shift : 1;
            s->sum_shift += (shift > 0) ? (uint64_t)shift : 1;
        }
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
    s.elapsed_sec = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_nsec - start.tv_nsec) / 1e9;

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

/* ---------------------------------------------------------------
 *        Utility: Build Pattern Hash Table for Fast Lookup
 * --------------------------------------------------------------- */
void buildPatternHashTable(Pattern *patterns, int numPatterns, int minLength, PatternList *hashTable) {
    // For each pattern, add its index to the hash table entry
    // corresponding to the character at position minLength-1
    for (int p = 0; p < numPatterns; p++) {
        if (patterns[p].length < minLength) continue;

        unsigned char ch = (unsigned char)patterns[p].pattern[minLength - 1];

        // Add pattern index to the hash table entry for this character
        PatternList *list = &hashTable[ch];
        if (list->count >= list->capacity) {
            int newCapacity = (list->capacity == 0) ? 8 : list->capacity * 2;
            int *newIndices = (int *)track_malloc((size_t)newCapacity * sizeof(int));
            if (list->indices) {
                memcpy(newIndices, list->indices, (size_t)list->count * sizeof(int));
                track_free(list->indices);
            }
            list->indices = newIndices;
            list->capacity = newCapacity;
        }
        list->indices[list->count++] = p;

        // If case-insensitive, also add to the alternate case
        if (patterns[p].nocase && isalpha((unsigned char)ch)) {
            unsigned char altCh = (unsigned char)(isupper((unsigned char)ch)
                                                   ? tolower((unsigned char)ch)
                                                   : toupper((unsigned char)ch));
            PatternList *altList = &hashTable[altCh];
            if (altList->count >= altList->capacity) {
                int newCapacity = (altList->capacity == 0) ? 8 : altList->capacity * 2;
                int *newIndices = (int *)track_malloc((size_t)newCapacity * sizeof(int));
                if (altList->indices) {
                    memcpy(newIndices, altList->indices, (size_t)altList->count * sizeof(int));
                    track_free(altList->indices);
                }
                altList->indices = newIndices;
                altList->capacity = newCapacity;
            }
            altList->indices[altList->count++] = p;
        }
    }
}

/* ---------------------------------------------------------------
 *          Utility: Free Pattern Hash Table Memory
 * --------------------------------------------------------------- */
void freePatternHashTable(PatternList *hashTable) {
    for (int i = 0; i < MAX_CHAR; i++) {
        if (hashTable[i].indices) {
            track_free(hashTable[i].indices);
            hashTable[i].indices = NULL;
            hashTable[i].count = 0;
            hashTable[i].capacity = 0;
        }
    }
}
