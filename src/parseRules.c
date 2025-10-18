#include "wm.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "parseRules.h"
#define CONTENT_START 9

/**
 * Reference for snort rule format: https://www.splunk.com/en_us/blog/learn/snort-rules.html
 */

// this file is for parsing snort rules, will figure out how to then verify pcap in a system
PatternSet *parseSnort(char *snortRules[], int numRules) {
    // alert tcp any any -> any any (msg:"XSS Attack - script tag detected"; content:"<script>"; nocase; sid:1003; rev:1;)
    PatternSet *ps = malloc(sizeof(PatternSet));
    int currPattern = 0;
    int terminate;
    ps->pattern_count = 0;
    for (int i = 0; i < numRules; i++) {
        char *ptr = strstr(snortRules[i], "content:");
        
        if (ptr != NULL) {
            char *content = &ptr[CONTENT_START];
            char *content_end = strstr(content, "\"");
            terminate = content_end - content;
            
            char newstr[terminate + 1];
            strncpy(newstr, content, terminate);
            newstr[terminate] = '\0';

            strcpy(ps->patterns[currPattern], newstr);
            ps->patterns[currPattern][terminate] = '\0';
            currPattern++;
            ps->pattern_count++;
        }
    }

    return ps;
}

WuManberTables *createTable(char *snortRules[], int numRules) {
    PatternSet *ps = parseSnort(snortRules, numRules);
    WuManberTables *tbl = malloc(sizeof(WuManberTables));

    wm_prepare_patterns(ps);

    wm_build_tables(ps, tbl);

    printf("hi %d\n", tbl->pat_len[0]);

    return tbl;
}