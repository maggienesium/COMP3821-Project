/*
 *              Boyer-Moore String Matching Algorithm
 *
 * ---------------------------------------------------------------
 * This file implements the Boyer-Moore String Matching algorithm which only
 * works with one pattern string. Hence, the overall time complexity will be
 * fairly bad as we need to iterate through all the patterns and match it.
 * Reference:
 * https://medium.com/@siddharth.21/the-boyer-moore-string-search-algorithm-674906cab162,
 * slightly changed to break when first match is found.
 * https://medium.com/@neethamadhu.ma/good-suffix-rule-in-boyer-moore-algorithm-explained-simply-9d9b6d20a773
 * https://www.geeksforgeeks.org/dsa/boyer-moore-algorithm-for-pattern-searching/
 *
 * R. S. Boyer, J. S. Moore,
 *   "A Fast String Searching Algorithm,”
 *   CACM 20(10):762–772 (1977).
 * --------------------------------------------------------------- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define RULESET_PATH "../../../data/ruleset/snort3-community-rules/snort3-community.rules"

#include "bm.h"
#include "../../parse/analytics.h"
#include "../../parse/parseRules.h"
#include "../WM/wm.h"

BMPatterns *bm_preprocessing(PatternSet *ps) {
    BMPatterns *bm_patterns = track_malloc(sizeof(BMPatterns));
    bm_patterns->patterns = track_malloc(sizeof(PatternTable) * (size_t) ps->pattern_count);
    bm_patterns->num_patterns = ps->pattern_count;

    for (int i = 0; i < ps->pattern_count; i++) {
        char *pattern = ps->patterns[i];
        PatternTable *curr_pattern = &bm_patterns->patterns[i];
        curr_pattern->pattern = track_malloc(sizeof(char) * (strlen(pattern) + 1));

        strcpy(curr_pattern->pattern, pattern);

        // initialse pattern table with length values
        for (int k = 0; k < ALPHABET_SIZE; k++) {
            curr_pattern->badCharTable[k] = NOT_IN_PATTERN;
        }

        int j = 0;
        for (; pattern[j] != '\0'; j++) {
            if (j > curr_pattern->badCharTable[(int)pattern[j]]) {
                curr_pattern->badCharTable[(int)(unsigned char)pattern[j]] = j;
            }
            curr_pattern->goodSuffixTable[j] = 0;
        }

        curr_pattern->pattern_length = j;
        int index = j;
        int k = j + 1;
        curr_pattern->borderTable = track_calloc((size_t)j + 1, sizeof(int));
        curr_pattern->borderTable[index] = k;

        while (index > 0) {
            while (k <= curr_pattern->pattern_length && pattern[index - 1] != pattern[k - 1]) {
                if (curr_pattern->goodSuffixTable[k] == 0) {
                    curr_pattern->goodSuffixTable[k] = k - 1;
                }
                k = curr_pattern->borderTable[k];
            }
            index--;
            k--;
            curr_pattern->borderTable[index] = k;
        }

        k = curr_pattern->borderTable[0];
        index = 0;
        for (; index <= curr_pattern->pattern_length; index++) {
            if (curr_pattern->goodSuffixTable[index] == 0) {
                curr_pattern->goodSuffixTable[index] = k;
            }

            if (index == k) {
                k = curr_pattern->borderTable[k];
            }
        }
    }

    return bm_patterns;
}

void bm_search(BMPatterns *bm, const char *text, size_t text_len) {
    AlgorithmStats s = {0};
    s.algorithm_name = "BM (Only with Bad Character Heuristic)";
    s.file_size = (uint64_t)bm->num_patterns;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int shift = 0;
    for (int i = 0; i < bm->num_patterns; i++) {
        shift = 0;

        PatternTable curr_table = bm->patterns[i];
        int j = curr_table.pattern_length - 1;
        while ((size_t)(shift + curr_table.pattern_length) - 1 < text_len) {
            // test starting from the final character in the pattern to
            // to the start of the text
            while (j >= 0 && curr_table.pattern[j] != '\0' && curr_table.pattern[j] == text[shift + j]) {
                j--;
            }

            if (j < 0) {
                // then we have a match at that shift value
                s.exact_matches++;

                break;
            } else {
                // utilise bad character heuristic since we have already
                // compared everything to the right of pattern position at mismatch
                // , can align shift to be the next index such that mismatch in text = last
                // occurence of char in pattern if in pattern, else shift 1.
                // also, can use good suffix heuristic, and skip such that
                // the next prefix matches
                int bad_skip_past_mismatch = bm->patterns[i].badCharTable[(int)(unsigned char)text[shift + j]];
                int skip_past_mismatch = bad_skip_past_mismatch;
                if (shift + j + 1 <= bm->patterns[i].pattern_length) {
                    int good_skip_past_mismatch = bm->patterns[i].goodSuffixTable[shift + j + 1];

                    if (bad_skip_past_mismatch < good_skip_past_mismatch) {
                        skip_past_mismatch = good_skip_past_mismatch;
                    }
                }

                if (skip_past_mismatch > 0 && j - skip_past_mismatch > 1) {
                    shift += j - skip_past_mismatch;
                } else {
                    shift++;
                }
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    s.elapsed_sec = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_nsec - start.tv_nsec) / 1e9;

    compute_throughput(&s);
    print_algorithm_stats(&s);
}

void bm_free_tables(BMPatterns *bm) {
    if (bm == NULL) {
        return;
    }

    for (int i = 0; i < bm->num_patterns; i++) {
        track_free(bm->patterns[i].borderTable);
        track_free(bm->patterns[i].pattern);
    }

    track_free(bm->patterns);

    track_free(bm);
    return;
}

// int main(void) {
//     printf("\n[+] Loading Snort rules from: %s\n", RULESET_PATH);
//     PatternSet *ps = loadSnortRulesFromFile(RULESET_PATH);
//     if (!ps) {
//         fprintf(stderr, "[-] Failed to load rules from %s\n", RULESET_PATH);
//         return EXIT_FAILURE;
//     }
//     printf("[+] Loaded %d patterns\n", ps->pattern_count);

//     BMPatterns *bm = bm_preprocessing(ps);

//     const char *badUrl = "this is my message with content base64, cmd.exe and password=testing";
//     bm_search(bm, badUrl, strlen(badUrl));

//     print_memory_stats("Active Algorithm", global_mem_stats);

//     for (int i = 0; i < ps->pattern_count; i++)
//         free(ps->rule_refs[i]);
//     free(ps->rule_refs);
//     free(ps);

//     free(global_mem_stats);

//     return 0;
// }
