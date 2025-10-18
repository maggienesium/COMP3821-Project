#include "wm.h"
#include <string.h>
#include <stdio.h>
#include "parseRules.h"
#include <stdlib.h>

// main file used to test parsing a set of snort rules and creating wu-mamber
int main(void) {
    char *rules[] = {
        "alert tcp any any -> any any (msg:\"Directory Traversal - /etc/passwd\"; content:\"/etc/passwd\"; sid:1004; rev:1;)",
        "alert tcp any any -> any any (msg:\"Command Injection - cmd.exe\"; content:\"cmd.exe\"; nocase; sid:1005; rev:1;)",
        "alert tcp any any -> any any (msg:\"FTP Anonymous Login\"; content:\"USER anonymous\"; nocase; sid:1006; rev:1;)",
        "alert tcp any any -> any any (msg:\"MALWARE - Backdoor string detected\"; content:\"backdoor\"; nocase; sid:1007; rev:1;)",
        "alert tcp any any -> any any (msg:\"HTTP - Admin panel access\"; content:\"admin\"; nocase; sid:1008; rev:1;)",
        "alert tcp any any -> any any (msg:\"Suspicious - Base64 encoding detected\"; content:\"base64\"; nocase; sid:1009; rev:1;)",
        "alert tcp any any -> any any (msg:\"Password in cleartext\"; content:\"password=\"; nocase; sid:1010; rev:1;)"
    };

    PatternSet *ps = parseSnort(rules, 7);
    WuManberTables *tbls = createTable(rules, 7);

    for (int i = 0; i < 7; i++) {
        printf("%s\n", ps->patterns[i]);
    }

    const char *badUrl = "base64";
    // should work, not sure why isn't
    wm_search((const unsigned char *)badUrl, strlen(badUrl), ps, tbls);

    free(ps);
    free(tbls);

    return 0;
}