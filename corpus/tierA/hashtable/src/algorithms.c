#include "program.h"
// @algorithm fnv/fnv1a-32
ALETHEIA_TARGET uint32_t fnv1a_32(const uint8_t *buf, size_t len) {
    uint32_t hash = UINT32_C(0x811c9dc5);
    for (size_t i = 0; i < len; ++i) hash = (hash ^ buf[i]) * UINT32_C(0x01000193);
    return hash;
}
// @algorithm fnv/fnv1-32
ALETHEIA_TARGET uint32_t fnv1_32(const uint8_t *buf, size_t len) {
    uint32_t hash = UINT32_C(0x811c9dc5);
    for (size_t i = 0; i < len; ++i) hash = (hash * UINT32_C(0x01000193)) ^ buf[i];
    return hash;
}
// @algorithm djb2/add
ALETHEIA_TARGET uint32_t djb2(const char *s) {
    uint32_t hash = 5381;
    while (*s) hash = hash * 33u + (uint8_t)*s++;
    return hash;
}
// @algorithm djb2/add
ALETHEIA_TARGET uint32_t djb2_buf(const uint8_t *buf, size_t len) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < len; ++i) hash = hash * 33u + buf[i];
    return hash;
}
// @algorithm djb2/xor
ALETHEIA_TARGET uint32_t djb2a_buf(const uint8_t *buf, size_t len) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < len; ++i) hash = (hash * 33u) ^ buf[i];
    return hash;
}
