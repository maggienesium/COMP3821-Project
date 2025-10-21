#ifndef HASHTABLE_H
#define HASHTABLE_H
#define INITIAL_RULES 10000 // number of rules from WM implementation

struct PatternRule {
    char *pattern;
    char *rule;
    struct PatternRule *next;
};

struct HashTable {
    struct PatternRule **blocks;
    int numBlocks;
    int numRules;
};

int hash(char *pattern);

/**
 * Function to get the corresponding rule to a given pattern.
 * Returns the rule.
 */
char *hashTableGet(struct HashTable *h, char *pattern);

/**
 * Function that creates a new Hash Table.
 */
struct HashTable *hashTableNew(void);

/**
 * Function which inserts a pattern-rule pair into an existing hash table.
 */
void HashTableInsert(struct HashTable *ht, char *pattern, char *rule);

#endif