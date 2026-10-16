#include "program.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
// @algorithm none
// @category control.main
int main(int argc, char **argv) {
    if (argc > 2) {fputs("usage: <in>\n", stderr); return 2;}
    FILE *stream = stdin;
    if (argc == 2 && strcmp(argv[1], "-") != 0) {
        stream = fopen(argv[1], "rb");
        if (stream == NULL) {fputs("input error\n", stderr); return 1;}
    }
    uint8_t input[4097], output[8193];
    size_t length = fread(input, 1, 4096, stream);
    int failed = ferror(stream) || (length == 4096 && fgetc(stream) != EOF);
    if (stream != stdin && fclose(stream) != 0) failed = 1;
    if (failed || length > 4096) {fputs("input error\n", stderr); return 1;}
    input[length] = 0;
    (void)output;
    uint64_t result = 0;
    result = proto_encode(1, input, length, output, sizeof output);
    printf("%016" PRIx64 "\n", result);
    return 0;
}
