#include "../wm.h"
#include <string.h>
#include <stdio.h>
#include "parseRules.h"
#include "hashTable.h"
#include <stdlib.h>

// main file used to test parsing a set of snort rules and creating wu-mamber table
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

    struct HashTable *table = hashTableNew();

    PatternSet *ps = addSnortRules(rules, 7, table);
    WuManberTables *tbls = createTable(ps);

    const char *badUrl = "this is my message with content base64, cmd.exe and password=testing";
    wm_search((const unsigned char *)badUrl, strlen(badUrl), ps, tbls);

    free(table);
    free(ps);
    free(tbls);

    return 0;
}