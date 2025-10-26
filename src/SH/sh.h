#ifndef SRC_SH_SH_H_
#define SRC_SH_SH_H_

#include <stdint.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 *                          Constants
 * --------------------------------------------------------------- */
#define MAX_CHAR           256
#define MAX_FILE_SIZE      10485760   /* 10 MB */
#define MAX_PATTERN_SIZE   256
#define MAX_PATTERNS       10000
#define MAX_LINE_LENGTH    4096

/* ---------------------------------------------------------------
 * Struct: Pattern
 *
 * Represents a single parsed Snort rule pattern.
 * Each pattern includes:
 *   - Raw pattern string (may include hex-encoded bytes)
 *   - Rule metadata (sid, message, nocase flag)
 * --------------------------------------------------------------- */
typedef struct {
    char *pattern;
    int   length;
    int   id;
    char *msg;
    int   sid;
    int   nocase;
} Pattern;

/* ---------------------------------------------------------------
 *                Function Prototypes (Parsing & Loading)
 * --------------------------------------------------------------- */

int parseHexBytes(const char *input, char *output, int maxLen);
char *extractContent(const char *rule, int *nocase);
char *extractMsg(const char *rule);
int extractSid(const char *rule);
int loadSnortRules(const char *filename, Pattern *patterns, int maxPatterns);

/* ---------------------------------------------------------------
 *                      Function Prototypes
 * --------------------------------------------------------------- */
void buildSetHorspoolShiftTable(Pattern *patterns, int numPatterns, int *shiftTable);
int compareChar(char a, char b, int nocase);
void setHorspoolSearch(char *text, uint64_t textLength,
                       Pattern *patterns, int numPatterns,
                       int *shiftTable, int minLength, FILE *alertFile);

void performSetHorspool(char *text, uint64_t textLength,
                        Pattern *patterns, int numPatterns,
                        const char *alertFile);

/* ---------------------------------------------------------------
 *                       Main Entry Point
 * --------------------------------------------------------------- */

/**
 * Standalone CLI driver (for experimentation).
 * Usage: ./set_horspool <rules_file> <pcap_file>
 */
int main(int argc, char *argv[]);

#endif  // SRC_SH_SH_H_
