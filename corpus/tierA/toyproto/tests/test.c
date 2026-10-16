#include "program.h"
#include "native-check.h"
#include <string.h>
#include <stdlib.h>
int main(void) {
    uint8_t encoded[64], out[32], type = 0; uint64_t value = 0;
    CHECK(varint_put(300, encoded) == 2 && encoded[0] == 0xac && encoded[1] == 2);
    CHECK(varint_get(encoded, 2, &value) == 2 && value == 300);
    CHECK(varint_put(UINT64_MAX, encoded) == 10 && varint_get(encoded, 10, &value) == 10 && value == UINT64_MAX);
    memset(encoded, 255, 10); CHECK(varint_get(encoded, 10, &value) == 0 && varint_get(encoded, 1, &value) == 0);
    const uint8_t in[] = {1,0,255}; size_t n = proto_encode(7, in, 3, encoded, sizeof encoded), capacity = sizeof out;
    CHECK(n == 7 && proto_decode(encoded, n, &type, out, &capacity) == 0 && type == 7 && capacity == 3 && memcmp(out, in, 3) == 0);
    encoded[n-1] ^= 1; capacity = sizeof out; CHECK(proto_decode(encoded, n, &type, out, &capacity) == -1);
    CHECK(proto_encode(1, in, 3, encoded, 3) == 0);
    /* rotl32(0x9e3779b9,13)=0xef3733c6; adding 0x7f4a7c15 modulo 2^32 gives this value. */
    CHECK(proto_handshake(0) == UINT32_C(0x6e81afdb));
    uint8_t oversized[12] = {0xa5, 1, 255,255,255,255,255,255,255,255,255,1};
    capacity = SIZE_MAX; CHECK(proto_decode(oversized, sizeof oversized, &type, out, &capacity) == -1);
    printf("ok %u\n", checks);
    return 0;
}
