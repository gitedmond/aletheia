#include "program.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
// @algorithm none
// @category memory.copy
// @roles out,buf,len
ALETHEIA_TARGET void *my_memcpy(void *destination, const void *source, size_t length) {
    uint8_t *out = destination; const uint8_t *in = source;
    for (size_t i = 0; i < length; ++i) out[i] = in[i];
    return destination;
}
// @algorithm none
// @category memory.set
ALETHEIA_TARGET void *my_memset(void *destination, int value, size_t length) {
    uint8_t *out = destination;
    for (size_t i = 0; i < length; ++i) out[i] = (uint8_t)value;
    return destination;
}
// @algorithm none
// @category memory.compare
ALETHEIA_TARGET int my_memcmp(const void *left, const void *right, size_t length) {
    const uint8_t *a = left, *b = right;
    for (size_t i = 0; i < length; ++i) if (a[i] != b[i]) return (int)a[i] - b[i];
    return 0;
}
// @algorithm none
// @category memory.alloc_wrapper
ALETHEIA_TARGET void *xmalloc(size_t length) { return malloc(length == 0 ? 1 : length); }
