#include "../wm.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "parseRules.h"
#include "hashTable.h"
#define CONTENT_START 9

/**
 * Reference for snort rule format: https://www.splunk.com/en_us/blog/learn/snort-rules.html
 * Snort rule options: https://docs.snort.org/rules/options/payload/
 * This file contains functions is for adding snort rules to a hash table, and
 * the content into Wu-Manber pattern sets, and I will then figure out how to
 * then verify PCAPs in a system.
 */

// Function which adds the relevant pattern specified in a rule to the Wu-Manber
// Pattern Set.
PatternSet *addContentToTable(char *snortRule, PatternSet *ps, int *currPattern,
                              struct HashTable *table) {
    char *ptr = strstr(snortRule, "content:");

    if (ptr == NULL) {
        return ps;
    }
    
    char *content = &ptr[CONTENT_START];
    char *content_end = strstr(content, "\"");
    int terminate = content_end - content;
    
    char newstr[terminate + 1];
    strncpy(newstr, content, terminate);
    newstr[terminate] = '\0';

    strcpy(ps->patterns[*currPattern], newstr);
    ps->patterns[*currPattern][terminate] = '\0';

    // add pattern and rule to the hash table
    HashTableInsert(table, ps->patterns[*currPattern], snortRule);
    
    (*currPattern)++;
    ps->pattern_count++;

    return ps;
}

// Function for adding snort rules initially before processing PCAPs, with a 
// Hash Table storing each StringMatchingContent-Rule pair.
PatternSet *addSnortRules(char **snortRules, int numRules, struct HashTable *table) {
    PatternSet *ps = malloc(sizeof(PatternSet));
    int currPattern = 0;
    ps->pattern_count = 0;

    for (int i = 0; i < numRules; i++) {
        addContentToTable(snortRules[i], ps, &currPattern, table);
    }

    return ps;
}

// Function creating tables for Wu-Manber once a pattern set is generated.
WuManberTables *createTable(PatternSet *ps) {
    WuManberTables *tbl = malloc(sizeof(WuManberTables));

    wm_prepare_patterns(ps);

    wm_build_tables(ps, tbl);

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