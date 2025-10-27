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
 * --------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "ac.h"
#include "../../parse/analytics.h"

/* ---------------------------------------------------------------
 *   Convert a character to lowercase (for case-insensitive mode).
 * --------------------------------------------------------------- */
static inline unsigned char to_lower_char(unsigned char c) {
    return (unsigned char)tolower(c);
}

/* ---------------------------------------------------------------
 *   Allocate and initialize an empty Aho–Corasick automaton.
 * --------------------------------------------------------------- */
AhoCorasick *ac_create(void) {
    AhoCorasick *ac = track_malloc(sizeof(AhoCorasick));
    if (!ac) {
        fprintf(stderr, "Memory allocation failed for AhoCorasick\n");
        exit(EXIT_FAILURE);
    }

    ac->capacity = 8;
    ac->nodes = track_malloc((size_t)ac->capacity * sizeof(ACNode));
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
 * --------------------------------------------------------------- */
void ac_add_pattern(AhoCorasick *ac, const char *pattern) {
    if (!ac || !pattern || !*pattern) return;

    int state = 0;
    for (int i = 0; pattern[i] != '\0'; i++) {
        unsigned char c = to_lower_char((unsigned char)pattern[i]);
        if (ac->nodes[state].transitions[c] == -1) {
            if (ac->node_count >= ac->capacity) {
                ac->capacity *= 2;
                ac->nodes = track_realloc(ac->nodes, (size_t)ac->capacity * sizeof(ACNode));
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
    node->output = track_realloc(node->output, (size_t)(node->output_count + 1) * sizeof(char *));
    node->output[node->output_count] = (char *)pattern;
    node->output_count++;
}

/* ---------------------------------------------------------------
 *   Compute failure links using BFS traversal and merge outputs.
 * --------------------------------------------------------------- */
void ac_build(AhoCorasick *ac) {
    if (!ac) return;

    int *queue = track_malloc((size_t)ac->node_count * sizeof(int));
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
                node->output = track_realloc(node->output,
                    (size_t)(node->output_count + fail_node->output_count) * sizeof(char *));
                for (int i = 0; i < fail_node->output_count; i++)
                    node->output[node->output_count++] = fail_node->output[i];
            }
        }
    }

    track_free(queue);
}

/* ---------------------------------------------------------------
 *   Perform Aho–Corasick search and print analytics summary.
 * --------------------------------------------------------------- */
void ac_search(AhoCorasick *ac, const char *text, size_t len) {
    if (!ac || !text) return;

    AlgorithmStats s = {0};
    s.algorithm_name = "Aho–Corasick";
    s.file_size = (uint64_t)len;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int state = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)tolower((unsigned char)text[i]);
        s.chars_scanned++;
        s.transitions++;

        while (ac->nodes[state].transitions[c] == -1 && state != 0) {
            state = ac->nodes[state].fail_state;
            s.fail_steps++;
        }
        state = ac->nodes[state].transitions[c];
        if (state == -1) state = 0;

        ACNode *node = &ac->nodes[state];
        s.matches += (uint64_t)node->output_count;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    s.elapsed_sec = ((end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec)) / 1e9;

    compute_throughput(&s);
    print_algorithm_stats(&s);
}


/* ---------------------------------------------------------------
 * Free all dynamically allocated memory associated with automaton.
 * --------------------------------------------------------------- */
void ac_destroy(AhoCorasick *ac) {
    if (!ac) return;
    for (int i = 0; i < ac->node_count; i++) {
        track_free(ac->nodes[i].output);
    }
    track_free(ac->nodes);
    track_free(ac);
}
