
#include <ctype.h>
#include <string.h>

/* ---------------------------------------------------------------
 *  Removes leading and trailing whitespace from a string read
 *  from a Snort ruleset file. This is used when reading and
 *  preprocessing each line of a ruleset before parsing Snort
 *  content patterns.
 * --------------------------------------------------------------- */
static inline void trim(char *s) {
    if (!s) return;
    char *start = s;
    while (isspace((unsigned char)*start)) {
        start++;
    }

    // All-space string
    if (*start == 0) {
        *s = '\0';
        return;
    }

    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    end[1] = '\0';

    // Move trimmed string to the beginning if needed
    if (s != start) {
        memmove(s, start, (size_t)(end - start) + 2);
    }
}
