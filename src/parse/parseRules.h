#ifndef SRC_PARSE_PARSERULES_H_
#define SRC_PARSE_PARSERULES_H_

#include "../algorithms/WM/wm.h"

/* ---------------------------------------------------------------
 *                        Parsing API
 * --------------------------------------------------------------- */
static inline void trim(char *s);
PatternSet *addContentToTable(char *snortRule, PatternSet *ps, int *currPattern);
PatternSet *loadSnortRulesFromFile(const char *filename);
WuManberTables *createTable(PatternSet *ps, int use_bloom);

#endif  // SRC_PARSE_PARSERULES_H_
