#include "aletheia.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// @algorithm none
// @category io.file.read
ALETHEIA_TARGET int read_input(const char *path, uint8_t **out, size_t *length) {
    const size_t limit = 16u * 1024u * 1024u;
    FILE *stream = path == NULL || strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
    if (stream == NULL) return -1;
    size_t capacity = 4096, size = 0;
    uint8_t *data = malloc(capacity + 1);
    if (data == NULL) { if (stream != stdin) fclose(stream); return -1; }
    int byte;
    while ((byte = fgetc(stream)) != EOF) {
        if (size == limit) { free(data); if (stream != stdin) fclose(stream); return -1; }
        if (size == capacity) {
            size_t next = capacity * 2;
            uint8_t *grown = realloc(data, next + 1);
            if (grown == NULL) { free(data); if (stream != stdin) fclose(stream); return -1; }
            data = grown;
            capacity = next;
        }
        data[size++] = (uint8_t)byte;
    }
    int failed = ferror(stream);
    if (stream != stdin && fclose(stream) != 0) failed = 1;
    if (failed) { free(data); return -1; }
    data[size] = 0;
    *out = data;
    *length = size;
    return 0;
}
