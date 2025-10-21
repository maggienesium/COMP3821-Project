#include "hashTable.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/**
 * Hash Table Implementation, utilised and changed from COMP2521's implementation
 * at https://cgi.cse.unsw.edu.au/~cs2521/23T3/lectures/slides/week08mon-hash-tables.pdf
*/

// Hash function
int hash(char *pattern) {
    int val = 0;
    for (int i = 0; pattern[i] != '\0'; i++) {
        val += pattern[i];
    }

    return val % INITIAL_RULES;
}

// Function which generates a new hash table.
struct HashTable *hashTableNew(void) {
    struct HashTable *table = malloc(sizeof(struct HashTable));
    table->blocks = calloc(INITIAL_RULES, sizeof(struct PatternRule *));
    table->numBlocks = INITIAL_RULES;
    table->numRules = 0;

    return table;
}

// Function that returns the rule mapping to a pattern
char *hashTableGet(struct HashTable *table, char *pattern) {
    int val = hash(pattern);

    struct PatternRule *curr = table->blocks[val];
    for (; curr->next != NULL || curr->pattern != pattern; curr = curr->next);

    if (curr->next == NULL) {
        return NULL;
    }

    return curr->rule;
}

// Insert helper function which inserts a Pattern rule in a linked list
void insert(struct PatternRule *list, char *pattern, char *rule) {
    struct PatternRule *pair = malloc(sizeof(struct PatternRule));
    pair->pattern = pattern;
    pair->rule = rule;

    if (list == NULL) {
        list = pair;
        return;
    }

    struct PatternRule *curr = list;
    for (; curr->next != NULL; curr = curr->next);
    
    curr->next = pair;
}

// Hash table insert function.
void HashTableInsert(struct HashTable *ht, char *pattern, char *rule) {
    int val = hash(pattern);
    insert(ht->blocks[val], pattern, rule);
}