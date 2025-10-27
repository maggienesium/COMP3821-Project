#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "../algorithms/WM/wm.h"
#include "../algorithms/AC/ac.h"
#include "../algorithms/SH/sh.h"
#include "../parse/analytics.h"
#include "../parse/parseRules.h"

#define RULESET_PATH "./data/ruleset/snort3-community-rules/snort3-community.rules"
#define TESTS_PATH   "./data/tests/pcaps"

/* ---------------------------------------------------------------
 *                        Algorithm selection
 * --------------------------------------------------------------- */
typedef enum {
    ALG_WM_DET,   // Wu–Manber deterministic
    ALG_WM_PROB,  // Wu–Manber probabilistic
    ALG_AC,       // Aho–Corasick
    ALG_SH        // Set–Horspool
} AlgorithmType;

/* ---------------------------------------------------------------
 *              Prompt user to choose algorithm
 * --------------------------------------------------------------- */
static AlgorithmType ask_user_algorithm(void) {
    char choice;
    printf("\nSelect Algorithm:\n");
    printf("  (d) Wu–Manber (Deterministic Prefix Hash)\n");
    printf("  (p) Wu–Manber (Probabilistic Bloom Filter)\n");
    printf("  (a) Aho–Corasick Automaton\n");
    printf("  (h) Set–Horspool Multi-Pattern Search\n");
    printf("Enter choice [d/p/a/h]: ");
    fflush(stdout);
    scanf(" %c", &choice);

    switch (choice) {
        case 'a': case 'A': return ALG_AC;
        case 'p': case 'P': return ALG_WM_PROB;
        case 'h': case 'H': return ALG_SH;
        default: return ALG_WM_DET;
    }
}

/* ---------------------------------------------------------------
 *          Scan a single file with chosen algorithm
 * --------------------------------------------------------------- */
static void scan_file(const char *filepath, PatternSet *ps,
                      WuManberTables *tbl, AhoCorasick *ac,
                      Pattern *sh_patterns, int sh_count,
                      AlgorithmType alg) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return;

    fseek(fp, 0, SEEK_END);
    int64_t size = ftell(fp);
    rewind(fp);
    if (size <= 0) {
        fclose(fp);
        return;
    }

    char *buffer = malloc((size_t)size + 1);
    if (!buffer) {
        fclose(fp);
        return;
    }
    fread(buffer, 1, (size_t)size, fp);
    buffer[size] = '\0';
    fclose(fp);

    const char *alg_name =
        (alg == ALG_AC) ? "Aho–Corasick" :
        (alg == ALG_WM_PROB) ? "Wu–Manber (Probabilistic)" :
        (alg == ALG_SH) ? "Set–Horspool" :
        "Wu–Manber (Deterministic)";

    printf("\n=== Scanning (%s): %s ===\n", alg_name, filepath);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    switch (alg) {
        case ALG_AC:
            ac_search(ac, buffer, (size_t)size);
            break;
        case ALG_WM_DET:
        case ALG_WM_PROB:
            wm_search((const unsigned char *)buffer, (int)size, ps, tbl);
            break;
        case ALG_SH:
            performSetHorspool(buffer, (uint64_t)size, sh_patterns, sh_count);
            break;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("[+] %s Completed in %.6f seconds\n", alg_name, elapsed);

    free(buffer);
}

/* ---------------------------------------------------------------
 *            Walk directory and scan all .pcap files
 * --------------------------------------------------------------- */
static void walk_directory(const char *base_path, PatternSet *ps,
                           WuManberTables *tbl, AhoCorasick *ac,
                           Pattern *sh_patterns, int sh_count,
                           AlgorithmType alg) {
    DIR *dir = opendir(base_path);
    if (!dir) return;

    struct dirent *entry;
    char path[1024];

    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);
        struct stat st;
        if (stat(path, &st) == -1)
            continue;

        if (S_ISDIR(st.st_mode)) {
            walk_directory(path, ps, tbl, ac, sh_patterns, sh_count, alg);
        } else if (S_ISREG(st.st_mode)) {
            const char *ext = strrchr(entry->d_name, '.');
            if (ext && strcmp(ext, ".pcap") == 0)
                scan_file(path, ps, tbl, ac, sh_patterns, sh_count, alg);
        }
    }
    closedir(dir);
}

int main(void) {
    AlgorithmType alg = ask_user_algorithm();

    printf("\n[+] Loading Snort rules from: %s\n", RULESET_PATH);
    PatternSet *ps = loadSnortRulesFromFile(RULESET_PATH);
    if (!ps) {
        fprintf(stderr, "[-] Failed to load rules from %s\n", RULESET_PATH);
        return EXIT_FAILURE;
    }
    printf("[+] Loaded %d patterns\n", ps->pattern_count);

    global_mem_stats = calloc(1, sizeof(MemoryStats));

    switch (alg) {
        case ALG_AC: {
            printf("[+] Building Aho–Corasick automaton...\n");
            AhoCorasick *ac = ac_create();
            for (int i = 0; i < ps->pattern_count; i++)
                ac_add_pattern(ac, ps->patterns[i]);
            ac_build(ac);

            printf("\n[+] Scanning all files under: %s\n", TESTS_PATH);
            walk_directory(TESTS_PATH, ps, NULL, ac, NULL, 0, ALG_AC);
            ac_destroy(ac);
            break;
        }

        case ALG_WM_DET:
        case ALG_WM_PROB: {
            int use_bloom = (alg == ALG_WM_PROB);
            WuManberTables *tbl = track_malloc(sizeof(WuManberTables));
            wm_build_tables(ps, tbl, use_bloom);

            printf("\n[+] Scanning all files under: %s\n", TESTS_PATH);
            walk_directory(TESTS_PATH, ps, tbl, NULL, NULL, 0, alg);

            wm_free_tables(tbl);
            track_free(tbl);
            break;
        }

        case ALG_SH: {
            printf("[+] Preparing Set–Horspool patterns...\n");
            Pattern *sh_patterns = track_calloc((size_t)ps->pattern_count, sizeof(Pattern));
            for (int i = 0; i < ps->pattern_count; i++) {
                sh_patterns[i].pattern = ps->patterns[i];
                sh_patterns[i].length = (int)strlen(ps->patterns[i]);
                sh_patterns[i].id = i;
                sh_patterns[i].nocase = 0;
            }

            printf("\n[+] Scanning all files under: %s\n", TESTS_PATH);
            walk_directory(TESTS_PATH, ps, NULL, NULL, sh_patterns, ps->pattern_count, ALG_SH);

            track_free(sh_patterns);
            break;
        }
    }

    print_memory_stats("Active Algorithm", global_mem_stats);

    for (int i = 0; i < ps->pattern_count; i++)
        free(ps->rule_refs[i]);
    free(ps->rule_refs);
    free(ps);

    free(global_mem_stats);

    return 0;
}
