#ifndef PARSERULES_H
#define PARSERULES_H

#include "wm.h"

PatternSet *parseSnort(char *snortRules[], int numRules);
WuManberTables *createTable(char *snortRules[], int numRules);

#endif