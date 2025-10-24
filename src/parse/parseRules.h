#ifndef PARSERULES_H
#define PARSERULES_H

#include "../WM/wm.h"

static inline void trim(char *s);
PatternSet *addContentToTable(char *snortRule, PatternSet *ps, int *currPattern);
PatternSet *loadSnortRulesFromFile(const char *filename);
WuManberTables *createTable(PatternSet *ps, int use_bloom);

#endif