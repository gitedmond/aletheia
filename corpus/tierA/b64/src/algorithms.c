#include "program.h"
static const char standard_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char url_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
// @algorithm base64/std-padded
// @category encoding.base64.encode
ALETHEIA_TARGET size_t b64_encode(const uint8_t *in, size_t len, char *out) {
    size_t pos = 0;
    for (size_t i = 0; i < len; i += 3) {
        size_t remaining = len - i;
        uint32_t bits = (uint32_t)in[i] << 16;
        if (remaining > 1) bits |= (uint32_t)in[i + 1] << 8;
        if (remaining > 2) bits |= in[i + 2];
        out[pos++] = standard_alphabet[(bits >> 18) & 63];
        out[pos++] = standard_alphabet[(bits >> 12) & 63];
        out[pos++] = remaining > 1 ? standard_alphabet[(bits >> 6) & 63] : '=';
        out[pos++] = remaining > 2 ? standard_alphabet[bits & 63] : '=';
    }
    return pos;
}
// @algorithm base64/url-nopad
// @category encoding.base64.encode
ALETHEIA_TARGET size_t b64_encode_url(const uint8_t *in, size_t len, char *out) {
    size_t pos = 0;
    for (size_t i = 0; i < len; i += 3) {
        size_t remaining = len - i;
        uint32_t bits = (uint32_t)in[i] << 16;
        if (remaining > 1) bits |= (uint32_t)in[i + 1] << 8;
        if (remaining > 2) bits |= in[i + 2];
        out[pos++] = url_alphabet[(bits >> 18) & 63];
        out[pos++] = url_alphabet[(bits >> 12) & 63];
        if (remaining > 1) out[pos++] = url_alphabet[(bits >> 6) & 63];
        if (remaining > 2) out[pos++] = url_alphabet[bits & 63];
    }
    return pos;
}
// @algorithm none
// @category encoding.base64.decode
static int decode_digit(unsigned char byte) {
    if (byte >= 'A' && byte <= 'Z') return byte - 'A';
    if (byte >= 'a' && byte <= 'z') return byte - 'a' + 26;
    if (byte >= '0' && byte <= '9') return byte - '0' + 52;
    if (byte == '+') return 62;
    if (byte == '/') return 63;
    return -1;
}
// @algorithm base64/std-padded-decode
// @category encoding.base64.decode
ALETHEIA_TARGET ptrdiff_t b64_decode(const char *in, size_t len, uint8_t *out) {
    if (len % 4 != 0 || len / 4 > (size_t)PTRDIFF_MAX / 3) return -1;
    size_t pos = 0;
    for (size_t i = 0; i < len; i += 4) {
        int a = decode_digit((unsigned char)in[i]);
        int b = decode_digit((unsigned char)in[i + 1]);
        int c = in[i + 2] == '=' ? 0 : decode_digit((unsigned char)in[i + 2]);
        int d = in[i + 3] == '=' ? 0 : decode_digit((unsigned char)in[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        if (in[i + 2] == '=') {
            if (in[i + 3] != '=' || i + 4 != len || (b & 15) != 0) return -1;
        } else if (in[i + 3] == '=' && (i + 4 != len || (c & 3) != 0)) return -1;
        uint32_t bits = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[pos++] = (uint8_t)(bits >> 16);
        if (in[i + 2] != '=') out[pos++] = (uint8_t)(bits >> 8);
        if (in[i + 3] != '=') out[pos++] = (uint8_t)bits;
    }
    return (ptrdiff_t)pos;
}
// @algorithm none
// @category util.other
ALETHEIA_TARGET size_t b64_encoded_len(size_t len) {
    if (len > SIZE_MAX - 2 || (len + 2) / 3 > SIZE_MAX / 4) return SIZE_MAX;
    return 4 * ((len + 2) / 3);
}
