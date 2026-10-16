#include "program.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
// @algorithm none
// @category encoding.other
ALETHEIA_TARGET size_t varint_put(uint64_t value, uint8_t *out) {
    size_t count = 0;
    do {uint8_t byte = (uint8_t)(value & 127); value >>= 7; out[count++] = (uint8_t)(byte | (value ? 128 : 0));} while (value != 0);
    return count;
}
// @algorithm none
// @category encoding.other
ALETHEIA_TARGET size_t varint_get(const uint8_t *buf, size_t len, uint64_t *out) {
    uint64_t value = 0;
    for (size_t i = 0; i < len && i < 10; ++i) {
        uint8_t byte = buf[i];
        if (i == 9 && byte > 1) return 0;
        value |= (uint64_t)(byte & 127) << (7*i);
        if ((byte & 128) == 0) {*out = value; return i+1;}
    }
    return 0;
}
// @algorithm none
// @category protocol.encode
ALETHEIA_TARGET size_t proto_encode(uint8_t type, const uint8_t *payload, size_t len, uint8_t *out, size_t capacity) {
    uint8_t encoded[10]; size_t width = varint_put(len, encoded);
    if (capacity < 3 + width || len > capacity - 3 - width) return 0;
    out[0] = 0xa5; out[1] = type; memcpy(out+2, encoded, width); memcpy(out+2+width, payload, len);
    uint8_t check = type; for (size_t i = 0; i < len; ++i) check ^= payload[i];
    out[2+width+len] = check; return 3+width+len;
}
// @algorithm none
// @category protocol.decode
ALETHEIA_TARGET int proto_decode(const uint8_t *frame, size_t length, uint8_t *type, uint8_t *payload, size_t *capacity) {
    if (length < 4 || frame[0] != 0xa5) return -1;
    uint64_t size; size_t width = varint_get(frame+2, length-2, &size);
    if (width == 0 || width > length-3) return -1;
    if (size != length-3-width || size > *capacity) return -1;
    uint8_t check = frame[1]; for (size_t i = 0; i < (size_t)size; ++i) check ^= frame[2+width+i];
    if (check != frame[length-1]) return -1;
    memcpy(payload, frame+2+width, (size_t)size); *type = frame[1]; *capacity = (size_t)size; return 0;
}
// @algorithm none
// @category protocol.handshake
ALETHEIA_TARGET uint32_t proto_handshake(uint32_t nonce) {
    nonce ^= UINT32_C(0x9e3779b9); nonce = (nonce << 13) | (nonce >> 19);
    return nonce + UINT32_C(0x7f4a7c15);
}
