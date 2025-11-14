// Define the POSIX source to have access to clock_gettime and CLOCK_MONOTONIC
#if !defined(_WIN32) || defined(__CYGWIN__)
#define _POSIX_C_SOURCE 199309L
#endif

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
#include "../algorithms/BM/bm.h"
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
    ALG_SH,       // Set–Horspool
    ALG_BM        // Boyer-Moore
} AlgorithmType;

// /* ---------------------------------------------------------------
//  *              Prompt user to choose algorithm
//  * --------------------------------------------------------------- */
// static AlgorithmType ask_user_algorithm(void) {
//     char choice;
//     printf("\nSelect Algorithm:\n");
//     printf("  (d) Wu–Manber (Deterministic Prefix Hash)\n");
//     printf("  (p) Wu–Manber (Probabilistic Bloom Filter)\n");
//     printf("  (a) Aho–Corasick Automaton\n");
//     printf("  (h) Set–Horspool Multi-Pattern Search\n");
//     printf("  (b) Boyer-Moore Multi-Pattern Variant");
//     printf("Enter choice [d/p/a/h/b]: ");
//     fflush(stdout);
//     scanf(" %c", &choice);

//     switch (choice) {
//         case 'a': case 'A': return ALG_AC;
//         case 'p': case 'P': return ALG_WM_PROB;
//         case 'h': case 'H': return ALG_SH;
//         case 'b': case 'B': printf("Hi!"); return ALG_BM;
//         default: return ALG_WM_DET;
//     }
// }

/* ---------------------------------------------------------------
 *          Scan a single file with chosen algorithm
 * --------------------------------------------------------------- */
static void scan_file(const char *filepath, PatternSet *ps,
                      WuManberTables *tbl, AhoCorasick *ac,
                      Pattern *sh_patterns, int sh_count, BMPatterns *bm,
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
        (alg == ALG_BM) ? "Boyer-Moore":
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
        case ALG_BM:
            bm_search(bm, buffer, (size_t)size);
            break;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    printf("[+] %s Completed in %.6f seconds\n", alg_name, elapsed);

    free(buffer);
}

// /* ---------------------------------------------------------------
//  *            Walk directory and scan all .pcap files
//  * --------------------------------------------------------------- */
// static void walk_directory(const char *base_path, PatternSet *ps,
//                            WuManberTables *tbl, AhoCorasick *ac,
//                            Pattern *sh_patterns, int sh_count, BMPatterns *bm,
//                            AlgorithmType alg) {
//     DIR *dir = opendir(base_path);
//     if (!dir) return;

//     struct dirent *entry;
//     char path[1024];

//     while ((entry = readdir(dir))) {
//         if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
//             continue;

//         snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);
//         struct stat st;
//         if (stat(path, &st) == -1)
//             continue;

//         if (S_ISDIR(st.st_mode)) {
//             walk_directory(path, ps, tbl, ac, sh_patterns, sh_count, bm, alg);
//         } else if (S_ISREG(st.st_mode)) {
//             const char *ext = strrchr(entry->d_name, '.');
//             if (ext && strcmp(ext, ".pcap") == 0)
//                 scan_file(path, ps, tbl, ac, sh_patterns, sh_count, bm, alg);
//         }
//     }
//     closedir(dir)
// }

int main(int argc, char *argv[]) {                
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <algorithm_choice> <file_to_scan>\n", argv[0]);
        fprintf(stderr, "Algorithm choices: a, d, p, h\n");
        return EXIT_FAILURE;
    }

    char choice = argv[1][0];
    const char *filepath = argv[2];
    AlgorithmType alg;

    switch (choice) {
        case 'a': alg = ALG_AC; break;
        case 'd': alg = ALG_WM_DET; break;
        case 'p': alg = ALG_WM_PROB; break;
        case 'h': alg = ALG_SH; break;
         case 'b': alg= ALG_BM; break;
        default:
            fprintf(stderr, "Invalid algorithm choice: %c\n", choice);
            return EXIT_FAILURE;
    }

    PatternSet *ps = loadSnortRulesFromFile(RULESET_PATH);
    if (!ps) {
        fprintf(stderr, "[-] Failed to load rules from %s\n", RULESET_PATH);
        return EXIT_FAILURE;
    }

    // Calculate and print ruleset stats
    uint64_t total_pattern_length = 0;
    for (int i = 0; i < ps->pattern_count; i++) {
        total_pattern_length += strlen(ps->patterns[i]);
    }
    double avg_pattern_length = (ps->pattern_count > 0) ? (double)total_pattern_length / (double)ps->pattern_count : 0.0;

    printf("Ruleset-Count: %d\n", ps->pattern_count);
    printf("Ruleset-Avg-Length: %.2f\n", avg_pattern_length);

    global_mem_stats = calloc(1, sizeof(MemoryStats));

    struct timespec build_start, build_end;
    double preprocessing_time = 0.0;

    switch (alg) {
        case ALG_AC: {
            AhoCorasick *ac = ac_create();
            clock_gettime(CLOCK_MONOTONIC, &build_start);
            for (int i = 0; i < ps->pattern_count; i++)
                ac_add_pattern(ac, ps->patterns[i]);
            ac_build(ac);

            clock_gettime(CLOCK_MONOTONIC, &build_end);
            scan_file(filepath, ps, NULL, ac, NULL, 0, NULL, ALG_AC);
            ac_destroy(ac);
            break;
        }

        case ALG_WM_DET:
        case ALG_WM_PROB: {
            int use_bloom = (alg == ALG_WM_PROB);
            WuManberTables *tbl = track_malloc(sizeof(WuManberTables));
            clock_gettime(CLOCK_MONOTONIC, &build_start);
            wm_build_tables(ps, tbl, use_bloom);
            clock_gettime(CLOCK_MONOTONIC, &build_end);
            scan_file(filepath, ps, tbl, NULL, NULL, 0, NULL, alg);
            wm_free_tables(tbl);
            track_free(tbl);
            break;
        }

        case ALG_SH: {
            Pattern *sh_patterns = track_calloc((size_t)ps->pattern_count, sizeof(Pattern));
            clock_gettime(CLOCK_MONOTONIC, &build_start);
            for (int i = 0; i < ps->pattern_count; i++) {
                sh_patterns[i].pattern = ps->patterns[i];
                sh_patterns[i].length = (int)strlen(ps->patterns[i]);
                sh_patterns[i].id = i;
                sh_patterns[i].nocase = 0;
            }
            clock_gettime(CLOCK_MONOTONIC, &build_end);
            scan_file(filepath, ps, NULL, NULL, sh_patterns, ps->pattern_count, 
                NULL, ALG_SH);
            track_free(sh_patterns);
            break;
        }

        case ALG_BM: {
            printf("[+] Pre-processing all patterns for Boyer-Moore...\n");
            BMPatterns *bm = bm_preprocessing(ps);

            printf("\n[+] Scanning all files under: %s\n", TESTS_PATH);
            scan_file(filepath, ps, NULL, NULL, NULL, 0, bm, ALG_BM);
            // free all tables
            bm_free_tables(bm);

            break;
        }
    }

    preprocessing_time = (double)(build_end.tv_sec - build_start.tv_sec) +
                         (double)(build_end.tv_nsec - build_start.tv_nsec) / 1e9;
    printf("Preprocessing-Time: %.6f\n", preprocessing_time);

    print_memory_stats("Active Algorithm", global_mem_stats);

    for (int i = 0; i < ps->pattern_count; i++)
        free(ps->rule_refs[i]);
    free(ps->rule_refs);
    free(ps);

    free(global_mem_stats);

    return 0;
}
