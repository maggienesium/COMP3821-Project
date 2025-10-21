#include "wm.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

int ask_user_mode(void) {
    char choice;
    printf("Select Mode:\n");
    printf("  (d) Deterministic Prefix Hash\n");
    printf("  (n) Non-Deterministic (Bloom Filter)\n");
    printf("Enter choice [d/n]: ");
    fflush(stdout);
    scanf(" %c", &choice);
    return (choice == 'n' || choice == 'N');
}

// THIS MAIN FILE IS JUST FOR TESTING WU-MANBER
int main(int argc, char *argv[]) {
    int use_bloom = ask_user_mode();

    PatternSet ps = {0};
    WuManberTables tbl = {0};

    // Example pattern loading
    strcpy(ps.patterns[0], "MALWARE");
    strcpy(ps.patterns[1], "EVIL");
    strcpy(ps.patterns[2], "BAD");
    ps.pattern_count = 3;

    int default_B = 2;  // (placeholder)
    wm_prepare_patterns(&ps, default_B);
    wm_build_tables(&ps, &tbl, use_bloom);

    // Example text to search
    const unsigned char text[] = "THIS_IS_BAD_EVILWARE";
    int text_len = strlen((const char *)text);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    wm_search(text, text_len, &ps, &tbl);

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("\n[+] Search completed in %.6f seconds\n", elapsed);

    if (use_bloom)
        bloom_free(&tbl.prefix_filter);  

    return 0;
}
