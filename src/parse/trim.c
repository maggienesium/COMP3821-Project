
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
        // The size is the length of the content (end - start + 1) plus the null terminator (+1),
        // which simplifies to (end - start + 2).
        memmove(s, start, (size_t)(end - start + 2));
    }
}
