#include "program.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// @algorithm none
int main(int argc, char **argv) {
    if (argc > 2) { fputs("usage: <in>\n", stderr); return 1; }
    uint8_t *input;
    size_t len;
    if (read_input(argc == 2 ? argv[1] : NULL, &input, &len) != 0) {
        fputs("error\n", stderr); return 1;
    }
    uint32_t sum = adler32_update(1, input, len);
    if (argc == 2 && strcmp(argv[1], "-") != 0 && sum_file(argv[1], &sum) != 0) {
        free(input); fputs("error\n", stderr); return 1;
    }
    printf("%08" PRIx32 "\n%08" PRIx32 "\n%04x\n", sum, adler32(input, len),
           (unsigned)fletcher16(input, len));
    free(input);
    return 0;
}
