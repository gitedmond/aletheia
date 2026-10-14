#include "program.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
// @algorithm none
int main(int argc, char **argv) {
    if (argc > 2) { fputs("usage: <in>\n", stderr); return 1; }
    uint8_t *input;
    size_t len;
    if (read_input(argc == 2 ? argv[1] : NULL, &input, &len) != 0) {
        fputs("error\n", stderr); return 1;
    }
    printf("%08" PRIx32 "\n%08" PRIx32 "\n%08" PRIx32 "\n%08" PRIx32 "\n%08" PRIx32 "\n",
           fnv1a_32(input, len), fnv1_32(input, len), djb2((const char *)input),
           djb2_buf(input, len), djb2a_buf(input, len));
    /* Encode binary input as a C-string key so embedded NULs remain distinguishable. */
    char *key = malloc(2 * len + 1);
    if (key == NULL) { free(input); fputs("error\n", stderr); return 1; }
    for (size_t i = 0; i < len; ++i) snprintf(key + 2 * i, 3, "%02x", (unsigned)input[i]);
    key[2 * len] = '\0';
    for (unsigned kind = 0; kind < 2; ++kind) {
        ht_t *table = ht_create(16, kind == 0 ? fnv1a_32 : djb2_buf);
        int value = 0;
        if (table == NULL || ht_insert(table, key, 1) != 0 || ht_lookup(table, key, &value) != 1) {
            ht_destroy(table); free(key); free(input); fputs("error\n", stderr); return 1;
        }
        printf("%08x\n", (unsigned)value);
        ht_destroy(table);
    }
    free(key);
    free(input);
    return 0;
}
