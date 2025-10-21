#ifndef PARSERULES_H
#define PARSERULES_H

#include "../wm.h"
#include "hashTable.h"

PatternSet *addSnortRules(char **snortRules, int numRule, struct HashTable *table);
WuManberTables *createTable(PatternSet *ps);

#endif