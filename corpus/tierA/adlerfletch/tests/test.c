#include "program.h"
#include "native-check.h"
#include <string.h>
// @algorithm none
int main(void) {
    const uint8_t vector[] = "Wikipedia";
    CHECK(adler32(NULL, 0) == 1);
    CHECK(adler32_update(1, NULL, 0) == 1);
    CHECK(adler32(vector, 9) == UINT32_C(0x11e60398));
    CHECK(adler32_update(1, vector, 9) == UINT32_C(0x11e60398));
    CHECK(adler32_update(adler32_update(1, vector, 4), vector + 4, 5) == UINT32_C(0x11e60398));
    CHECK(adler32((const uint8_t *)"a", 1) == UINT32_C(0x00620062));
    CHECK(fletcher16(NULL, 0) == 0);
    CHECK(fletcher16((const uint8_t *)"abcde", 5) == UINT16_C(0xc8f0));
    uint8_t repeated[70000];
    memset(repeated, 255, sizeof repeated);
    CHECK(adler32(repeated, sizeof repeated) == UINT32_C(0x2a286e81));
    FILE *file = fopen("input.tmp", "wb");
    CHECK(file != NULL);
    CHECK(fwrite(vector, 1, 9, file) == 9);
    CHECK(fclose(file) == 0);
    uint32_t sum = 0;
    CHECK(sum_file("input.tmp", &sum) == 0);
    CHECK(sum == UINT32_C(0x11e60398));
    CHECK(remove("input.tmp") == 0);
    CHECK(sum_file("absent.tmp", &sum) != 0);
    printf("ok %u\n", checks);
    return 0;
}
