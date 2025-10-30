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
 * R. S. Boyer, J. S. Moore,
 *   A Fast String Searching Algoritm,”
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

BMPatterns *generateBadCharacterTables(PatternSet *ps) {
    BMPatterns *bm_patterns = malloc(sizeof(BMPatterns));
    bm_patterns->patterns = malloc(sizeof(PatternTable) * ps->pattern_count);
    bm_patterns->num_patterns = ps->pattern_count;
    
    for (int i = 0; i < ps->pattern_count; i++) {
        char *pattern = ps->patterns[i];
        PatternTable *curr_pattern = &bm_patterns->patterns[i];
        curr_pattern->pattern = malloc(sizeof(char) * (strlen(pattern) + 1));
        
        strcpy(curr_pattern->pattern, pattern);

        // initialse pattern table with length values
        for (int k = 0; k < ALPHABET_SIZE; k++) {
            curr_pattern->badCharTable[k] = NOT_IN_PATTERN;
        }

        int j = 0;
        for (; pattern[j] != '\0'; j++) {
            if (j > curr_pattern->badCharTable[(int)pattern[j]]) {
                curr_pattern->badCharTable[(int)pattern[j]] = j;
            }
        }

        curr_pattern->pattern_length = j;
    }
    printf("%s\n", bm_patterns->patterns[0].pattern);
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
        printf("%d and %s\n", i, bm->patterns[i].pattern);
        int j = curr_table.pattern_length - 1;
        while (shift + curr_table.pattern_length - 1 < text_len) {
            // test starting from the final character in the pattern to
            // to the start of the text
            while (j >= 0 && curr_table.pattern[j] != '\0' && curr_table.pattern[j] == text[shift + j]) {
                j--;
            }

            if (j < 0) {
                // then we have a match at that shift value
                printf("%s at %d\n", curr_table.pattern, j);
                s.exact_matches++;
                
                break;
            } else {
                // utilise bad character heuristic since we have already
                // compared everything to the right of pattern position at mismatch
                // , can align shift to be the next index such that mismatch in text = last
                // occurence of char in pattern if in pattern, else shift 1.
                int skip_past_mismatch = bm->patterns[i].badCharTable[(int)text[shift + j]];
                if (skip_past_mismatch > 0 && j - skip_past_mismatch > 1) {
                    shift += j - skip_past_mismatch;
                } else {
                    shift++;
                }
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    s.elapsed_sec = ((end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec)) / 1e9;

    compute_throughput(&s);
    print_algorithm_stats(&s);
}

int main(void) {
    printf("\n[+] Loading Snort rules from: %s\n", RULESET_PATH);
    PatternSet *ps = loadSnortRulesFromFile(RULESET_PATH);
    if (!ps) {
        fprintf(stderr, "[-] Failed to load rules from %s\n", RULESET_PATH);
        return EXIT_FAILURE;
    }
    printf("[+] Loaded %d patterns\n", ps->pattern_count);

    BMPatterns *bm = generateBadCharacterTables(ps);

    const char *badUrl = "this is my message with content base64, cmd.exe and password=testing";
    bm_search(bm, badUrl, strlen(badUrl));

    print_memory_stats("Active Algorithm", global_mem_stats);

    for (int i = 0; i < ps->pattern_count; i++)
        free(ps->rule_refs[i]);
    free(ps->rule_refs);
    free(ps);

    free(global_mem_stats);

    return 0;
}
