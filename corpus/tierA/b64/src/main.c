#include "program.h"
#include <stdio.h>
#include <stdlib.h>
// @algorithm none
ALETHEIA_TARGET void print_bytes(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x", (unsigned)buf[i]);
    putchar('\n');
}
// @algorithm none
int main(int argc, char **argv) {
    if (argc > 2) { fputs("usage: <in>\n", stderr); return 1; }
    uint8_t *input;
    size_t len;
    if (read_input(argc == 2 ? argv[1] : NULL, &input, &len) != 0) {
        fputs("error\n", stderr); return 1;
    }
    size_t capacity = b64_encoded_len(len);
    char *encoded = malloc(capacity + 1);
    uint8_t *decoded = malloc(len + 1);
    if (encoded == NULL || decoded == NULL) {
        free(input); free(encoded); free(decoded); fputs("error\n", stderr); return 1;
    }
    size_t count = b64_encode(input, len, encoded);
    print_bytes((const uint8_t *)encoded, count);
    ptrdiff_t decoded_len = b64_decode(encoded, count, decoded);
    count = b64_encode_url(input, len, encoded);
    print_bytes((const uint8_t *)encoded, count);
    if (decoded_len < 0) {
        free(input); free(encoded); free(decoded); fputs("error\n", stderr); return 1;
    }
    print_bytes(decoded, (size_t)decoded_len);
    free(input);
    free(encoded);
    free(decoded);
    return 0;
}
