/* 
 *               Aho–Corasick Multi-Pattern Matcher
 *
 * ---------------------------------------------------------------
 * Implements the Aho–Corasick string matching algorithm for 
 * multiple pattern searches. Supports case-insensitive matching 
 * for ASCII text.
 *
 * Reference:
 *   A. V. Aho, M. J. Corasick,
 *   “Efficient String Matching: An Aid to Bibliographic Search,”
 *   CACM 18(6):333–340 (1975).
 * ---------------------------------------------------------------
 */

#include "ac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "../WM/wm.h"

/* ---------------------------------------------------------------
 * Struct: ACStats
 *
 * Tracks runtime analytics for a single Aho–Corasick search run:
 *    - Total characters scanned
 *    - State transitions
 *    - Failure link traversals
 *    - Matches found
 *    - Dynamic memory operations
 *    - Total elapsed time
 * ---------------------------------------------------------------
 */
typedef struct {
    uint64_t chars_scanned;
    uint64_t transitions;
    uint64_t fail_steps;
    uint64_t matches;
    uint64_t alloc_count;   // malloc/realloc calls
    uint64_t free_count;    // free calls
    size_t   total_bytes;   // total bytes allocated
    double   elapsed_sec;
} ACStats;

/*  Global analytics reference (used by memory wrappers) */
static ACStats *g_ac_stats = NULL;

/* ---------------------------------------------------------------
 *   Display collected runtime statistics after a search.
 * ---------------------------------------------------------------
 */
static void ac_print_analytics(const ACStats *s, int n) {
    printf("\n[Search Stats: Aho–Corasick]\n");
    printf("  Characters scanned   : %llu\n", (uint64_t)s->chars_scanned);
    printf("  State transitions    : %llu\n", (uint64_t)s->transitions);
    printf("  Fail link traversals : %llu\n", (uint64_t)s->fail_steps);
    printf("  Matches found        : %llu\n", (uint64_t)s->matches);
    printf("  Allocations          : %llu\n", (uint64_t)s->alloc_count);
    printf("  Frees                : %llu\n", (uint64_t)s->free_count);
    printf("  Total bytes alloc’d  : %zu bytes\n", s->total_bytes);
    printf("  Elapsed time         : %.6f sec\n", s->elapsed_sec);
    printf("  Throughput           : %.2f MB/s\n",
           s->elapsed_sec > 0 ? (n / (1024.0 * 1024.0)) / s->elapsed_sec : 0.0);
}

/* ---------------------------------------------------------------
 *   Convert a character to lowercase (for case-insensitive mode).
 * ---------------------------------------------------------------
 */
static inline unsigned char to_lower_char(unsigned char c) {
    return (unsigned char)tolower(c);
}

/* ---------------------------------------------------------------
 *   Memory wrappers that count allocations and total bytes
 *   for dynamic space complexity tracking.
 * ---------------------------------------------------------------
 */
void *ac_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr && g_ac_stats) {
        g_ac_stats->alloc_count++;
        g_ac_stats->total_bytes += size;
    }
    if (ptr && g_wm_global_stats) {
        g_wm_global_stats->alloc_count++;
        g_wm_global_stats->total_bytes += size;
    }
    return ptr;
}

void *ac_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (new_ptr && g_ac_stats) {
        g_ac_stats->alloc_count++;
        g_ac_stats->total_bytes += size;
    }
    if (new_ptr && g_wm_global_stats) {
        g_wm_global_stats->alloc_count++;
        g_wm_global_stats->total_bytes += size;
    }
    return new_ptr;
}

void ac_free_mem(void *ptr) {
    if (ptr && g_ac_stats)
        g_ac_stats->free_count++;
    if (ptr && g_wm_global_stats)
        g_wm_global_stats->free_count++;
    free(ptr);
}


/* ---------------------------------------------------------------
 *   Allocate and initialize an empty Aho–Corasick automaton.
 * ---------------------------------------------------------------
 */
AhoCorasick *ac_create(void) {
    AhoCorasick *ac = ac_malloc(sizeof(AhoCorasick));
    if (!ac) {
        fprintf(stderr, "Memory allocation failed for AhoCorasick\n");
        exit(EXIT_FAILURE);
    }

    ac->capacity = 8;
    ac->nodes = ac_malloc((size_t)ac->capacity * sizeof(ACNode));
    if (!ac->nodes) {
        fprintf(stderr, "Memory allocation failed for trie nodes\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 256; i++)
        ac->nodes[0].transitions[i] = -1;

    ac->nodes[0].fail_state = 0;
    ac->nodes[0].output = NULL;
    ac->nodes[0].output_count = 0;
    ac->node_count = 1;

    return ac;
}

/* ---------------------------------------------------------------
 *          Insert a pattern string into the automaton.
 * ---------------------------------------------------------------
 */
void ac_add_pattern(AhoCorasick *ac, const char *pattern) {
    if (!ac || !pattern || !*pattern) return;

    int state = 0;
    for (int i = 0; pattern[i] != '\0'; i++) {
        unsigned char c = to_lower_char((unsigned char)pattern[i]);
        if (ac->nodes[state].transitions[c] == -1) {
            if (ac->node_count >= ac->capacity) {
                ac->capacity *= 2;
                ac->nodes = ac_realloc(ac->nodes, (size_t)ac->capacity * sizeof(ACNode));
                if (!ac->nodes) {
                    fprintf(stderr, "Failed to reallocate trie nodes\n");
                    exit(EXIT_FAILURE);
                }
            }

            int new_state = ac->node_count++;
            for (int j = 0; j < 256; j++)
                ac->nodes[new_state].transitions[j] = -1;

            ac->nodes[new_state].fail_state = 0;
            ac->nodes[new_state].output = NULL;
            ac->nodes[new_state].output_count = 0;

            ac->nodes[state].transitions[c] = new_state;
        }
        state = ac->nodes[state].transitions[c];
    }

    ACNode *node = &ac->nodes[state];
    node->output = ac_realloc(node->output, (size_t)(node->output_count + 1) * sizeof(char *));
    node->output[node->output_count] = strdup(pattern);
    node->output_count++;
}

/* ---------------------------------------------------------------
 *   Compute failure links using BFS traversal and merge outputs.
 * ---------------------------------------------------------------
 */
void ac_build(AhoCorasick *ac) {
    if (!ac) return;

    int *queue = ac_malloc((size_t)ac->node_count * sizeof(int));
    int front = 0, rear = 0;

    for (int c = 0; c < 256; c++) {
        int next = ac->nodes[0].transitions[c];
        if (next != -1) {
            ac->nodes[next].fail_state = 0;
            queue[rear++] = next;
        } else {
            ac->nodes[0].transitions[c] = 0;
        }
    }

    while (front < rear) {
        int state = queue[front++];

        for (int c = 0; c < 256; c++) {
            int next = ac->nodes[state].transitions[c];
            if (next == -1) continue;

            queue[rear++] = next;

            int fail = ac->nodes[state].fail_state;
            while (ac->nodes[fail].transitions[c] == -1)
                fail = ac->nodes[fail].fail_state;

            ac->nodes[next].fail_state = ac->nodes[fail].transitions[c];

            ACNode *node = &ac->nodes[next];
            ACNode *fail_node = &ac->nodes[node->fail_state];
            if (fail_node->output_count > 0) {
                node->output = ac_realloc(node->output,
                    (size_t)(node->output_count + fail_node->output_count) * sizeof(char *));
                for (int i = 0; i < fail_node->output_count; i++)
                    node->output[node->output_count++] = strdup(fail_node->output[i]);
            }
        }
    }

    ac_free_mem(queue);
}

/* ---------------------------------------------------------------
 *   Perform Aho–Corasick search and print analytics summary.
 * ---------------------------------------------------------------
 */
void ac_search(AhoCorasick *ac, const char *text) {
    if (!ac || !text) return;

    ACStats stats = {0};
    g_ac_stats = &stats;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int state = 0;
    int n = (int)strlen(text);

    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)tolower((unsigned char)text[i]);
        stats.chars_scanned++;
        stats.transitions++;

        while (ac->nodes[state].transitions[c] == -1 && state != 0) {
            state = ac->nodes[state].fail_state;
            stats.fail_steps++;
        }

        state = ac->nodes[state].transitions[c];
        if (state == -1) state = 0;

        ACNode *node = &ac->nodes[state];
        for (int j = 0; j < node->output_count; j++) {
            stats.matches++;
            printf("[+] Match found for \"%s\" at index %d\n",
                   node->output[j], i - (int)strlen(node->output[j]) + 1);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    stats.elapsed_sec = ((end.tv_sec - start.tv_sec) +
                         (end.tv_nsec - start.tv_nsec)) / 1e9;

    ac_print_analytics(&stats, n);
    g_ac_stats = NULL;
}

/* ---------------------------------------------------------------
 * Free all dynamically allocated memory associated with automaton.
 * ---------------------------------------------------------------
 */
void ac_destroy(AhoCorasick *ac) {
    if (!ac) return;

    for (int i = 0; i < ac->node_count; i++) {
        for (int j = 0; j < ac->nodes[i].output_count; j++)
            ac_free_mem(ac->nodes[i].output[j]);
        ac_free_mem(ac->nodes[i].output);
    }
    ac_free_mem(ac->nodes);
    ac_free_mem(ac);
}
