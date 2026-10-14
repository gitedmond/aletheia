#include "program.h"
#include "native-check.h"
#include <string.h>
// @algorithm none
int main(void) {
    const char *plain[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar", "Man", "M"};
    const char *encoded[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy", "TWFu", "TQ=="};
    for (size_t i = 0; i < sizeof plain / sizeof *plain; ++i) {
        uint8_t output[32];
        memset(output, 0xa5, sizeof output);
        size_t len = strlen(plain[i]), expected = strlen(encoded[i]);
        CHECK(b64_encoded_len(len) == expected);
        CHECK(b64_encode((const uint8_t *)plain[i], len, (char *)output) == expected);
        CHECK(memcmp(output, encoded[i], expected) == 0);
        CHECK(output[expected] == 0xa5);
        size_t url_len = expected;
        while (url_len && encoded[i][url_len - 1] == '=') --url_len;
        memset(output, 0xa5, sizeof output);
        CHECK(b64_encode_url((const uint8_t *)plain[i], len, (char *)output) == url_len);
        CHECK(memcmp(output, encoded[i], url_len) == 0 && output[url_len] == 0xa5);
        memset(output, 0xa5, sizeof output);
        CHECK(b64_decode(encoded[i], expected, output) == (ptrdiff_t)len);
        CHECK(memcmp(output, plain[i], len) == 0 && output[len] == 0xa5);
    }
    const uint8_t binary[] = {0xfb, 0xff};
    char out[8];
    CHECK(b64_encode(binary, 2, out) == 4 && memcmp(out, "+/8=", 4) == 0);
    CHECK(b64_encode_url(binary, 2, out) == 3 && memcmp(out, "-_8", 3) == 0);
    uint8_t decoded[8];
    CHECK(b64_decode("+/8=", 4, decoded) == 2 && memcmp(decoded, binary, 2) == 0);
    const char *invalid[] = {"A", "AAA", "=AAA", "A===", "AA=A", "AAAA====", "AA==AAAA", "AA?=", "-_8=", "AB==", "AAB="};
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i)
        CHECK(b64_decode(invalid[i], strlen(invalid[i]), decoded) == -1);
    uint8_t all[256], restored[256];
    char text[344];
    for (size_t i = 0; i < sizeof all; ++i) all[i] = (uint8_t)i;
    CHECK(b64_encode(all, sizeof all, text) == sizeof text);
    CHECK(b64_decode(text, sizeof text, restored) == sizeof all);
    CHECK(memcmp(all, restored, sizeof all) == 0);
    printf("ok %u\n", checks);
    return 0;
}
