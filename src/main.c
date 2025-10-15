#include "wm.h"
#include <string.h>
#include <stdio.h>


// THIS MAIN FILE IS JUST FOR TESTING WU-MANBER
int main(void) {
    PatternSet ps = { .pattern_count = 3 };
    strncpy(ps.patterns[0], "MALWARE", MAX_PATTERN_LEN);
    strncpy(ps.patterns[1], "EVIL", MAX_PATTERN_LEN);
    strncpy(ps.patterns[2], "BAD", MAX_PATTERN_LEN);

    WuManberTables tbl;

    wm_prepare_patterns(&ps);
    wm_build_tables(&ps, &tbl);

    const char *text = "THISBADFILEHASAVIRUSEVILMALWAREINSIDE";
    wm_search((const unsigned char *)text, strlen(text), &ps, &tbl);

    return 0;
}
