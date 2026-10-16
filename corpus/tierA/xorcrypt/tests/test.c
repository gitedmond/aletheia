#include "program.h"
#include "native-check.h"
#include <string.h>
#include <stdlib.h>
int main(void) {
    uint8_t data[] = {1,2,3,4,5}, original[5]; const uint8_t key[] = {1,2,3,4,5};
    memcpy(original, data, 5); xor_crypt(data, 5, key, 5); CHECK(data[0] == 0 && data[4] == 0);
    xor_crypt(data, 5, key, 5); CHECK(memcmp(data, original, 5) == 0);
    xor_crypt(data, 5, key, 0); CHECK(memcmp(data, original, 5) == 0);
    rc4_t ctx; CHECK(rc4_init(&ctx, key, 0) == -1 && rc4_init(&ctx, key, 5) == 0);
    uint8_t out[16] = {0}; const uint8_t expected[16] = {0xb2,0x39,0x63,0x05,0xf0,0x3d,0xc0,0x27,0xcc,0xc3,0x52,0x4a,0x0a,0x11,0x18,0xa8};
    rc4_crypt(&ctx, out, 5); rc4_crypt(&ctx, out+5, 11); CHECK(memcmp(out, expected, 16) == 0);
    CHECK(rc4_init(&ctx, key, 5) == 0); rc4_crypt(&ctx, out, 16);
    uint8_t zero[16] = {0}; CHECK(memcmp(out, zero, 16) == 0);
    printf("ok %u\n", checks);
    return 0;
}
