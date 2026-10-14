#include "program.h"
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
    crc32_table_init();
    if (!crc32_selftest()) { free(input); fputs("error\n", stderr); return 1; }
    hex_print32(crc32_update(0, input, len));
    hex_print32(crc32_bitwise(input, len));
    hex_print32(jamcrc(input, len));
    hex_print32(crc32_update_rt(0, input, len));
    free(input);
    return 0;
}
