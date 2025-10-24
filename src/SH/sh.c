#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define MAX_CHAR 256
#define MAX_FILE_SIZE 10485760
#define MAX_PATTERN_SIZE 256
#define MAX_PATTERNS 10000
#define MAX_LINE_LENGTH 4096


int totalComparisons = 0;
int totalOccurrences = 0;
int patternMatches[MAX_PATTERNS] = {0};


typedef struct {
    char* pattern;
    int length;
    int id;
    char* msg;
    int sid;
    int nocase;
} Pattern;


int parseHexBytes(const char* input, char* output, int maxLen) {
    int outIdx = 0;
    int i = 0;

    while (input[i] && outIdx < maxLen) {
        if (input[i] == '|') {
            i++;

            while (input[i] && input[i] != '|' && outIdx < maxLen) {
                if (isxdigit(input[i])) {
                    char hex[3] = {0};
                    hex[0] = input[i++];
                    if (input[i] && isxdigit(input[i])) {
                        hex[1] = input[i++];
                    }
                    output[outIdx++] = (char)strtol(hex, NULL, 16);

                    while (input[i] == ' ') i++;
                } else {
                    i++;
                }
            }
            if (input[i] == '|') i++;
        } else {
            output[outIdx++] = input[i++];
        }
    }
    return outIdx;
}


char* extractContent(const char* rule, int* nocase) {
    const char* start = strstr(rule, "content:\"");
    if (!start) return NULL;

    start += 9;
    const char* end = strchr(start, '"');
    if (!end) return NULL;

    int len = end - start;
    char* temp = (char*)malloc(len + 1);
    strncpy(temp, start, len);
    temp[len] = '\0';


    char* content = (char*)malloc(MAX_PATTERN_SIZE);
    int actualLen = parseHexBytes(temp, content, MAX_PATTERN_SIZE);
    content[actualLen] = '\0';


    *nocase = (strstr(end, "nocase") != NULL);

    free(temp);
    return content;
}


char* extractMsg(const char* rule) {
    const char* start = strstr(rule, "msg:\"");
    if (!start) return strdup("Unknown");

    start += 5;
    const char* end = strchr(start, '"');
    if (!end) return strdup("Unknown");

    int len = end - start;
    char* msg = (char*)malloc(len + 1);
    strncpy(msg, start, len);
    msg[len] = '\0';
    return msg;
}


int extractSid(const char* rule) {
    const char* start = strstr(rule, "sid:");
    if (!start) return 0;

    start += 4;
    return atoi(start);
}


int loadSnortRules(const char* filename, Pattern* patterns, int maxPatterns) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("Error: Could not open rules file '%s'\n", filename);
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    int count = 0;

    while (fgets(line, sizeof(line), fp) && count < maxPatterns) {

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;


        if (strncmp(line, "alert", 5) == 0 && strstr(line, "content:")) {
            int nocase = 0;
            char* content = extractContent(line, &nocase);

            if (content && strlen(content) > 0) {
                patterns[count].pattern = content;
                patterns[count].length = strlen(content);
                patterns[count].id = count;
                patterns[count].msg = extractMsg(line);
                patterns[count].sid = extractSid(line);
                patterns[count].nocase = nocase;
                count++;
            }
        }
    }

    fclose(fp);
    printf("Loaded %d patterns from Snort rules\n", count);
    return count;
}



void buildSetHorspoolShiftTable(Pattern* patterns, int numPatterns, int* shiftTable) {
    int minLength = patterns[0].length;


    for (int i = 1; i < numPatterns; i++) {
        if (patterns[i].length < minLength) {
            minLength = patterns[i].length;
        }
    }


    for (int i = 0; i < MAX_CHAR; i++) {
        shiftTable[i] = minLength;
    }


    for (int p = 0; p < numPatterns; p++) {

        for (int i = 0; i < minLength - 1; i++) {
            unsigned char ch = (unsigned char)patterns[p].pattern[i];
            int shift = minLength - 1 - i;


            if (shift < shiftTable[ch]) {
                shiftTable[ch] = shift;
            }


            if (patterns[p].nocase && isalpha(ch)) {
                unsigned char altCh = isupper(ch) ? tolower(ch) : toupper(ch);
                if (shift < shiftTable[altCh]) {
                    shiftTable[altCh] = shift;
                }
            }
        }
    }
}



int compareChar(char a, char b, int nocase) {
    if (nocase) {
        return tolower((unsigned char)a) == tolower((unsigned char)b);
    }
    return a == b;
}


void setHorspoolSearch(char* text, long textLength, Pattern* patterns, int numPatterns, int* shiftTable, int minLength, FILE* alertFile) {
    long pos = 0;

    while (pos <= textLength - minLength) {

        long windowEnd = pos + minLength - 1;

        int foundMatch = 0;
        int maxShift = shiftTable[(unsigned char)text[windowEnd]];


        for (int p = 0; p < numPatterns; p++) {
            int patternLen = patterns[p].length;


            if (pos + patternLen > textLength) continue;


            int matched = 1;
            for (long j = patternLen - 1; j >= 0; j--) {
                totalComparisons++;
                if (!compareChar(text[pos + j], patterns[p].pattern[j], patterns[p].nocase)) {
                    matched = 0;
                    break;
                }
            }

            if (matched) {

                totalOccurrences++;
                patternMatches[p]++;


                fprintf(alertFile, "[**] [1:%d:1] %s [**]\n", patterns[p].sid, patterns[p].msg);
                fprintf(alertFile, "Position: %ld, Pattern: \"", pos);
                for (int i = 0; i < patternLen && i < 50; i++) {
                    if (isprint((unsigned char)patterns[p].pattern[i])) {
                        fprintf(alertFile, "%c", patterns[p].pattern[i]);
                    } else {
                        fprintf(alertFile, "\\x%02X", (unsigned char)patterns[p].pattern[i]);
                    }
                }
                fprintf(alertFile, "\"\n\n");

                foundMatch = 1;


            }
        }


        if (foundMatch) {

            pos++;
        } else {

            pos += maxShift;
        }
    }
}



void performSetHorspool(char* text, long textLength, Pattern* patterns, int numPatterns, const char* alertFile) {
    printf("\n===== Set Horspool NIDS (Snort Rules) =====\n\n");

    if (numPatterns == 0) {
        printf("No patterns loaded!\n");
        return;
    }


    int minLength = patterns[0].length;
    for (int i = 1; i < numPatterns; i++) {
        if (patterns[i].length < minLength) {
            minLength = patterns[i].length;
        }
    }

    printf("Processing %d patterns from Snort rules (min length: %d)\n", numPatterns, minLength);
    printf("Text size: %.2f KB\n\n", textLength / 1024.0);


    int* shiftTable = (int*)malloc(MAX_CHAR * sizeof(int));
    buildSetHorspoolShiftTable(patterns, numPatterns, shiftTable);


    FILE* fp = fopen(alertFile, "w");
    if (fp == NULL) {
        printf("Error: Could not create alert file\n");
        free(shiftTable);
        return;
    }

    fprintf(fp, "===== Snort Alert Log =====\n");
    fprintf(fp, "Analyzed: %.2f KB\n", textLength / 1024.0);
    fprintf(fp, "Patterns: %d\n\n", numPatterns);


    clock_t start = clock();
    setHorspoolSearch(text, textLength, patterns, numPatterns, shiftTable, minLength, fp);
    clock_t end = clock();

    double cpuTime = ((double)(end - start)) / CLOCKS_PER_SEC;


    printf("\n===== Analysis Results =====\n");
    printf("Total character comparisons: %d\n", totalComparisons);
    printf("Total alerts triggered: %d\n", totalOccurrences);
    printf("Time taken: %.6f ms\n", cpuTime * 1000);
    printf("Throughput: %.2f MB/s\n\n", (textLength / (1024.0 * 1024.0)) / cpuTime);


    printf("Top 10 triggered rules:\n");
    typedef struct {
        int count;
        int idx;
    } RuleCount;

    RuleCount topRules[numPatterns];
    for (int i = 0; i < numPatterns; i++) {
        topRules[i].count = patternMatches[i];
        topRules[i].idx = i;
    }


    for (int i = 0; i < 10 && i < numPatterns; i++) {
        for (int j = i + 1; j < numPatterns; j++) {
            if (topRules[j].count > topRules[i].count) {
                RuleCount temp = topRules[i];
                topRules[i] = topRules[j];
                topRules[j] = temp;
            }
        }
    }

    for (int i = 0; i < 10 && i < numPatterns; i++) {
        if (topRules[i].count > 0) {
            int idx = topRules[i].idx;
            printf("  [SID %d] %d alerts - %s\n",
                   patterns[idx].sid, topRules[i].count, patterns[idx].msg);
        }
    }

    fprintf(fp, "\n===== Summary =====\n");
    fprintf(fp, "Total alerts: %d\n", totalOccurrences);
    fprintf(fp, "Character comparisons: %d\n", totalComparisons);
    fprintf(fp, "Analysis time: %.6f ms\n", cpuTime * 1000);

    fclose(fp);
    free(shiftTable);

    printf("\nAlerts written to: %s\n", alertFile);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <snort_rules_file> <pcap_file>\n", argv[0]);
        fprintf(stderr, "Example: %s rules/snort3-community.rules pcaps/test.pcap\n", argv[0]);
        return 1;
    }

    char* rulesFile = argv[1];
    char* pcapFile = argv[2];
    char* alertFile = "alerts.txt";

    printf("===== Set Horspool NIDS =====\n");
    printf("Rules file: %s\n", rulesFile);
    printf("PCAP file: %s\n\n", pcapFile);


    Pattern* patterns = (Pattern*)malloc(MAX_PATTERNS * sizeof(Pattern));
    if (!patterns) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    int numPatterns = loadSnortRules(rulesFile, patterns, MAX_PATTERNS);
    if (numPatterns == 0) {
        fprintf(stderr, "Error: No patterns loaded from rules file\n");
        free(patterns);
        return 1;
    }


    FILE* fp = fopen(pcapFile, "rb");
    if (fp == NULL) {
        printf("Error: Could not open file '%s'\n", pcapFile);
        free(patterns);
        return 1;
    }


    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileSize > MAX_FILE_SIZE) {
        printf("Warning: File size (%.2f MB) exceeds maximum (%.2f MB), truncating...\n",
               fileSize / (1024.0 * 1024.0), MAX_FILE_SIZE / (1024.0 * 1024.0));
        fileSize = MAX_FILE_SIZE;
    }

    printf("Reading PCAP file: %.2f KB\n", fileSize / 1024.0);


    char* data = (char*)malloc(fileSize + 1);
    if (data == NULL) {
        printf("Error: Memory allocation failed\n");
        fclose(fp);
        free(patterns);
        return 1;
    }

    size_t bytesRead = fread(data, 1, fileSize, fp);
    data[bytesRead] = '\0';
    fclose(fp);


    performSetHorspool(data, bytesRead, patterns, numPatterns, alertFile);


    for (int i = 0; i < numPatterns; i++) {
        free(patterns[i].pattern);
        free(patterns[i].msg);
    }
    free(patterns);
    free(data);

    return 0;
}