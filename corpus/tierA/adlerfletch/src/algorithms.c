#include "program.h"
#include <stdio.h>
// @algorithm adler32/zlib
ALETHEIA_TARGET uint32_t adler32_update(uint32_t adler, const uint8_t *buf, size_t len) {
    uint32_t a = adler & 65535u, b = adler >> 16;
    for (size_t i = 0; i < len; ++i) {
        a = (a + buf[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}
// @algorithm adler32/zlib
ALETHEIA_TARGET uint32_t adler32(const uint8_t *buf, size_t len) {
    return adler32_update(1, buf, len);
}
// @algorithm fletcher16/std
ALETHEIA_TARGET uint16_t fletcher16(const uint8_t *buf, size_t len) {
    uint32_t a = 0, b = 0;
    for (size_t i = 0; i < len; ++i) {
        a = (a + buf[i]) % 255u;
        b = (b + a) % 255u;
    }
    return (uint16_t)((b << 8) | a);
}
// @algorithm none
ALETHEIA_TARGET int sum_file(const char *path, uint32_t *out) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) return -1;
    uint8_t buffer[4096];
    uint32_t sum = 1;
    size_t count;
    while ((count = fread(buffer, 1, sizeof buffer, file)) != 0)
        sum = adler32_update(sum, buffer, count);
    int failed = ferror(file);
    if (fclose(file) != 0) failed = 1;
    if (failed) return -1;
    *out = sum;
    return 0;
}
