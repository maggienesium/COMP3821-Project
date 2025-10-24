#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../WM/wm.h"
#include "parseRules.h"

#define RULESET_PATH "./src/ruleset/snort3-community-rules/snort3-community.rules"
#define TESTS_PATH "./src/tests/pcaps" // root folder to walk

static int ask_user_mode(void) {
    char choice;
    printf("Select Mode:\n");
    printf("  (d) Deterministic Prefix Hash\n");
    printf("  (n) Non-Deterministic (Bloom Filter)\n");
    printf("Enter choice [d/n]: ");
    fflush(stdout);
    scanf(" %c", &choice);
    return (choice == 'n' || choice == 'N');
}

static void scan_file(const char *filepath, PatternSet *ps, WuManberTables *tbl) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);

    if (size <= 0) {
        fclose(fp);
        return;
    }

    char *buffer = malloc((size_t)size + 1);
    fread(buffer, 1, (size_t)size, fp);
    buffer[size] = '\0';
    fclose(fp);

    printf("\n=== Scanning: %s ===\n", filepath);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    wm_search((const unsigned char *)buffer, (int)size, ps, tbl);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("[+] Completed in %.6f seconds\n", elapsed);

    free(buffer);
}

static void walk_directory(const char *base_path, PatternSet *ps, WuManberTables *tbl) {
    DIR *dir = opendir(base_path);
    if (!dir) return;

    struct dirent *entry;
    char path[1024];

    while ((entry = readdir(dir))) {
        // skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);

        struct stat st;
        if (stat(path, &st) == -1) continue;

        if (S_ISDIR(st.st_mode)) {
            walk_directory(path, ps, tbl);
        } else if (S_ISREG(st.st_mode)) {
            const char *ext = strrchr(entry->d_name, '.');
            // Can add more file extensions here...
            if (ext && strcmp(ext, ".pcap") == 0) {
                scan_file(path, ps, tbl);
            }
        }
    }

    closedir(dir);
}

int main(void) {
    int use_bloom = ask_user_mode();

    printf("[+] Loading Snort rules from: %s\n", RULESET_PATH);
    PatternSet *ps = loadSnortRulesFromFile(RULESET_PATH);
    if (!ps) {
        fprintf(stderr, "Failed to load rules from %s\n", RULESET_PATH);
        return EXIT_FAILURE;
    }

    printf("[+] Loaded %d patterns\n", ps->pattern_count);

    WuManberTables *tbl = createTable(ps, use_bloom);

    printf("[+] Scanning all files under: %s\n", TESTS_PATH);
    walk_directory(TESTS_PATH, ps, tbl);

    wm_free_tables(tbl);
    free(tbl);
    for (int i = 0; i < ps->pattern_count; i++)
        free(ps->rule_refs[i]);
    free(ps->rule_refs);
    free(ps);

    return 0;
}
