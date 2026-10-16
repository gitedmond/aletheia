#include "program.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
// @algorithm none
// @category crypto.cipher.xor
ALETHEIA_TARGET void xor_crypt(uint8_t *buf, size_t len, const uint8_t *key, size_t key_len) {
    if (key_len == 0) return;
    for (size_t i = 0; i < len; ++i) buf[i] ^= key[i % key_len];
}
// @algorithm none
// @category crypto.cipher.rc4
ALETHEIA_TARGET int rc4_init(rc4_t *ctx, const uint8_t *key, size_t len) {
    if (len == 0) return -1;
    for (size_t i = 0; i < 256; ++i) ctx->s[i] = (uint8_t)i;
    uint8_t j = 0;
    for (size_t i = 0; i < 256; ++i) {j = (uint8_t)(j + ctx->s[i] + key[i % len]); uint8_t temp = ctx->s[i]; ctx->s[i] = ctx->s[j]; ctx->s[j] = temp;}
    ctx->i = 0; ctx->j = 0; return 0;
}
// @algorithm none
// @category crypto.cipher.rc4
ALETHEIA_TARGET void rc4_crypt(rc4_t *ctx, uint8_t *buf, size_t len) {
    for (size_t n = 0; n < len; ++n) {
        ctx->i = (uint8_t)(ctx->i+1); ctx->j = (uint8_t)(ctx->j + ctx->s[ctx->i]);
        uint8_t temp = ctx->s[ctx->i]; ctx->s[ctx->i] = ctx->s[ctx->j]; ctx->s[ctx->j] = temp;
        buf[n] ^= ctx->s[(uint8_t)(ctx->s[ctx->i] + ctx->s[ctx->j])];
    }
}
