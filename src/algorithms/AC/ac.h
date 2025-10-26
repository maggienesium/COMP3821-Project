#ifndef SRC_ALGORITHMS_AC_AC_H_
#define SRC_ALGORITHMS_AC_AC_H_

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------
 *   Represents a node in the Aho–Corasick automaton.
 *   Each node stores:
 *     - Transition table (for all possible input symbols)
 *     - Failure link (used for backtracking)
 *     - Output list of matched patterns
 * ---------------------------------------------------------------
 */
typedef struct ACNode {
    int   transitions[256];
    int   fail_state;
    char **output;
    int   output_count;
} ACNode;

/* ---------------------------------------------------------------
 *   Container for the entire Aho–Corasick automaton,
 *   including dynamic array of nodes.
 * --------------------------------------------------------------- */
typedef struct {
    ACNode *nodes;
    int     node_count;
    int     capacity;
} AhoCorasick;

/* ---------------------------------------------------------------
 *                 Aho–Corasick Automaton API
 * --------------------------------------------------------------- */
AhoCorasick *ac_create(void);
void ac_add_pattern(AhoCorasick *ac, const char *pattern);
void ac_build(AhoCorasick *ac);
void ac_search(AhoCorasick *ac, const char *text);
void ac_destroy(AhoCorasick *ac);

/* ---------------------------------------------------------------
 *                  Memory Tracking Analytics
 * --------------------------------------------------------------- */
void *ac_realloc(void *ptr, size_t size);
void *ac_malloc(size_t size);
void ac_free_mem(void *ptr);

#endif  // SRC_ALGORITHMS_AC_AC_H_
