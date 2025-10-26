#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/stat.h>
#include "../WM/wm.h"
#include "../AC/ac.h"
#include "parseRules.h"

#define RULESET_PATH "./src/ruleset/snort3-community-rules/snort3-community.rules"
#define TESTS_PATH   "./src/tests/pcaps"

/* ---------------------------------------------------------------
 * Enum: AlgorithmType
 * ---------------------------------------------------------------
 * Distinguishes which pattern-matching algorithm to run.
 * --------------------------------------------------------------- */
typedef enum {
    ALG_WM_DET,   // Wu–Manber with deterministic prefix hashing
    ALG_WM_NDET,  // Wu–Manber with probabilistic Bloom filter
    ALG_AC        // Aho–Corasick automaton
} AlgorithmType;

/* ---------------------------------------------------------------
 * Global: WM analytics tracker
 * ---------------------------------------------------------------
 * Used by memory wrappers to record total allocations and bytes.
 * --------------------------------------------------------------- */
WMGlobalStats *g_wm_global_stats = NULL;

/* ---------------------------------------------------------------
 * Function: ask_user_algorithm
 *
 * Purpose:
 *   Prompt the user to choose between algorithms.
 * --------------------------------------------------------------- */
static AlgorithmType ask_user_algorithm(void) {
    char choice;
    printf("\nSelect Algorithm:\n");
    printf("  (d) Wu–Manber (Deterministic Prefix Hash)\n");
    printf("  (n) Wu–Manber (Non-Deterministic Bloom Filter)\n");
    printf("  (a) Aho–Corasick Automaton\n");
    printf("Enter choice [d/n/a]: ");
    fflush(stdout);
    scanf(" %c", &choice);

    if (choice == 'a' || choice == 'A')
        return ALG_AC;
    else if (choice == 'n' || choice == 'N')
        return ALG_WM_NDET;
    else
        return ALG_WM_DET;
}

/* ---------------------------------------------------------------
 * Function: scan_file_wm
 *
 * Purpose:
 *   Perform Wu–Manber search on a single file and report timing.
 * --------------------------------------------------------------- */
static void scan_file_wm(const char *filepath, PatternSet *ps, WuManberTables *tbl) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return;

    fseek(fp, 0, SEEK_END);
    int64_t pos_tmp = (int64_t)ftell(fp);
    if (pos_tmp < 0) {
        perror("ftell");
        fclose(fp);
        return;
    }
    uint64_t size = (uint64_t)pos_tmp;
    rewind(fp);


    if (size == 0) {
        fclose(fp);
        return;
    }

    char *buffer = malloc(size + 1);
    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);

    printf("\n=== Scanning (Wu–Manber): %s ===\n", filepath);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    wm_search((const unsigned char *)buffer, (int)size, ps, tbl);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("[+] WM Completed in %.6f seconds\n", elapsed);

    free(buffer);
}

/* ---------------------------------------------------------------
 * Function: scan_file_ac
 *
 * Purpose:
 *   Perform Aho–Corasick search on a single file and report timing.
 * --------------------------------------------------------------- */
static void scan_file_ac(const char *filepath, AhoCorasick *ac) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return;

    fseek(fp, 0, SEEK_END);
    int64_t pos_tmp = (int64_t)ftell(fp);
    if (pos_tmp < 0) {
        perror("ftell");
        fclose(fp);
        return;
    }
    uint64_t size = (uint64_t)pos_tmp;
    rewind(fp);


    if (size == 0) {
        fclose(fp);
        return;
    }

    char *buffer = malloc(size + 1);
    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);

    printf("\n=== Scanning (Aho–Corasick): %s ===\n", filepath);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    ac_search(ac, buffer);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("[+] AC Completed in %.6f seconds\n", elapsed);

    free(buffer);
}

/* ---------------------------------------------------------------
 * Function: walk_directory
 *
 * Purpose:
 *   Recursively walk a directory and scan all .pcap files.
 * --------------------------------------------------------------- */
static void walk_directory(const char *base_path, PatternSet *ps,
                           WuManberTables *tbl, AhoCorasick *ac,
                           AlgorithmType alg) {
    DIR *dir = opendir(base_path);
    if (!dir) return;

    struct dirent *entry;
    char path[1024];

    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);

        struct stat st;
        if (stat(path, &st) == -1)
            continue;

        if (S_ISDIR(st.st_mode)) {
            walk_directory(path, ps, tbl, ac, alg);
        } else if (S_ISREG(st.st_mode)) {
            const char *ext = strrchr(entry->d_name, '.');
            if (ext && strcmp(ext, ".pcap") == 0) {
                if (alg == ALG_AC)
                    scan_file_ac(path, ac);
                else
                    scan_file_wm(path, ps, tbl);
            }
        }
    }

    closedir(dir);
}

/* ---------------------------------------------------------------
 * Function: print_wm_space_analytics
 *
 * Purpose:
 *   Print total allocations and bytes tracked by wm_* wrappers.
 * --------------------------------------------------------------- */
static void print_wm_space_analytics(void) {
    if (!g_wm_global_stats) return;

    printf("\n[Space Complexity Summary]\n");
    printf("  Total allocations : %llu\n", (uint64_t)g_wm_global_stats->alloc_count);
    printf("  Total bytes used  : %llu bytes (%.2f MB)\n",
           (uint64_t)g_wm_global_stats->total_bytes,
           g_wm_global_stats->total_bytes / (1024.0 * 1024.0));
}

/* ---------------------------------------------------------------
 * Main Entry Point
 * --------------------------------------------------------------- */
int main(void) {
    AlgorithmType alg = ask_user_algorithm();

    printf("\n[+] Loading Snort rules from: %s\n", RULESET_PATH);
    PatternSet *ps = loadSnortRulesFromFile(RULESET_PATH);
    if (!ps) {
        fprintf(stderr, "[-] Failed to load rules from %s\n", RULESET_PATH);
        return EXIT_FAILURE;
    }

    printf("[+] Loaded %d patterns\n", ps->pattern_count);

    /* Initialize global WM analytics */
    g_wm_global_stats = calloc(1, sizeof(WMGlobalStats));

    if (alg == ALG_AC) {
        printf("[+] Building Aho–Corasick automaton...\n");
        AhoCorasick *ac = ac_create();

        for (int i = 0; i < ps->pattern_count; i++)
            ac_add_pattern(ac, ps->patterns[i]);

        ac_build(ac);

        printf("[+] Scanning all files under: %s\n", TESTS_PATH);
        walk_directory(TESTS_PATH, ps, NULL, ac, ALG_AC);

        ac_free_mem(ac);
    } else {
        int use_bloom = (alg == ALG_WM_NDET);
        WuManberTables *tbl = wm_malloc(sizeof(WuManberTables));
        wm_build_tables(ps, tbl, use_bloom);

        printf("[+] Scanning all files under: %s\n", TESTS_PATH);
        walk_directory(TESTS_PATH, ps, tbl, NULL, alg);

        wm_free_tables(tbl);
        wm_free(tbl);
    }

    print_wm_space_analytics();

    for (int i = 0; i < ps->pattern_count; i++)
        free(ps->rule_refs[i]);
    free(ps->rule_refs);
    free(ps);
    free(g_wm_global_stats);

    return 0;
}
