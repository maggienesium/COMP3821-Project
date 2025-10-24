#include "../WM/wm.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include "parseRules.h"

#define CONTENT_START 9

/* ---------------------------------------------------------------
 * Purpose: 
 *      Removes leading and trailing whitespace from a string 
 *      read from a Snort ruleset file.
 * 
 * Parameters:
 *   s   -  Pointer to the character buffer to trim
 *
 * Returns:
 *      None. The input string is modified directly.
 *   
 *  Notes:
 *      This is used when reading and preprocessing each line of 
 *      a ruleset before parsing Snort content patterns.
 * ---------------------------------------------------------------
 */
static void trim(char *s) {
    char *end;
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}


/* -------------------------------------------------------------------------
 * Purpose:
 *   Parses a single Snort rule line and extracts one or more `content:"..."` 
 *   strings from it. Each extracted content string is added to the given
 *   Wu–Manber PatternSet for later table construction.
 *
 * Parameters:
 *   snortRule   - A string containing one complete Snort rule line.
 *   ps          - Pointer to an initialized PatternSet structure.
 *   currPattern - Pointer to the current pattern index being filled.
 *
 * Returns:
 *   Pointer to the updated PatternSet containing all extracted patterns.
 *
 * References:
 *   Snort rule format overview:
 *     https://www.splunk.com/en_us/blog/learn/snort-rules.html
 *   Snort payload options:
 *     https://docs.snort.org/rules/options/payload/
 * -------------------------------------------------------------------------
 */
PatternSet *addContentToTable(char *snortRule, PatternSet *ps, int *currPattern) {
    char *ptr = strstr(snortRule, "content:");
    while (ptr) {
        char *content = &ptr[CONTENT_START];
        char *content_end = strstr(content, "\"");
        if (!content_end) break;

        size_t len = (size_t)(content_end - content);
        if (len >= MAX_PATTERN_LEN) len = MAX_PATTERN_LEN - 1;

        strncpy(ps->patterns[*currPattern], content, len);
        ps->patterns[*currPattern][len] = '\0';

        ps->rule_refs[*currPattern] = strdup(snortRule);
        ps->pattern_count++;
        (*currPattern)++;

        ptr = strstr(content_end, "content:");
    }
    return ps;
}

/* -------------------------------------------------------------------------
 * Purpose:
 *   Loads and parses all Snort rules from a specified ruleset file,
 *   automatically extracting every `content:"..."` pattern and storing
 *   it in a Wu–Manber PatternSet.
 *
 * Parameters:
 *   filename - Path to the Snort rules file (e.g., snort3-community.rules).
 *
 * Returns:
 *   Pointer to a fully populated PatternSet structure containing all
 *   extracted content patterns and rule references.
 * -------------------------------------------------------------------------
 */
PatternSet *loadSnortRulesFromFile(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror(filename);
        return NULL;
    }

    PatternSet *ps = malloc(sizeof(PatternSet));
    if (!ps) {
        fprintf(stderr, "Memory allocation failed for PatternSet.\n");
        exit(EXIT_FAILURE);
    }
    memset(ps, 0, sizeof(PatternSet));
    ps->rule_refs = malloc(MAX_PATTERNS * sizeof(char *));
    if (!ps->rule_refs) {
        fprintf(stderr, "Memory allocation failed for rule_refs.\n");
        exit(EXIT_FAILURE);
    }

    int currPattern = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (line[0] == '#' || strlen(line) < 5)
            continue;   // skip comments or empty lines

        addContentToTable(line, ps, &currPattern);
    }

    fclose(fp);
    ps->pattern_count = currPattern;
    return ps;
}

/* -------------------------------------------------------------------------
 * Purpose:
 *   Initializes and builds Wu–Manber tables based on a populated PatternSet.
 *
 * Parameters:
 *   ps        - Pointer to an initialized PatternSet containing patterns.
 *   use_bloom - Boolean flag: if non-zero, enables Bloom filter optimization.
 *
 * Returns:
 *   Pointer to an allocated WuManberTables structure ready for searching.
 * -------------------------------------------------------------------------
 */
WuManberTables *createTable(PatternSet *ps, int use_bloom) {
    WuManberTables *tbl = malloc(sizeof(WuManberTables));
    if (!tbl) {
        fprintf(stderr, "Memory allocation failed for WuManberTables.\n");
        exit(EXIT_FAILURE);
    }

    int default_B = 2;
    wm_prepare_patterns(ps, default_B);
    wm_build_tables(ps, tbl, use_bloom);

    return tbl;
}

/**
 * TODO: a function which accepts an incoming packet, processes it
 * before string matching and finally, snort rules are verified against it
 * packet with the below options I found relevant, need to check if we should 
 * consider these.
 * fast_pattern 
 * nocase
 * width
 * endian
 */
