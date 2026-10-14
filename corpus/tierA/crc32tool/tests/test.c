#include "program.h"
#include "native-check.h"
#include <string.h>
// @algorithm none
int main(void) {
    const uint8_t vector[] = "123456789";
    const uint8_t a[] = "a";
    CHECK(crc32_update(0, NULL, 0) == 0);
    CHECK(crc32_bitwise(NULL, 0) == 0);
    CHECK(jamcrc(NULL, 0) == UINT32_MAX);
    CHECK(crc32_update(0, vector, 9) == UINT32_C(0xcbf43926));
    CHECK(crc32_bitwise(vector, 9) == UINT32_C(0xcbf43926));
    CHECK(jamcrc(vector, 9) == UINT32_C(0x340bc6d9));
    CHECK(crc32_update(0, a, 1) == UINT32_C(0xe8b7be43));
    CHECK(crc32_update(crc32_update(0, vector, 4), vector + 4, 5) == UINT32_C(0xcbf43926));
    CHECK(crc32_update(UINT32_C(0x12345678), NULL, 0) == UINT32_C(0x12345678));
    crc32_table_init();
    CHECK(crc32_update_rt(0, vector, 9) == UINT32_C(0xcbf43926));
    CHECK(crc32_update_rt(crc32_update_rt(0, vector, 2), vector + 2, 7) == UINT32_C(0xcbf43926));
    CHECK(crc32_selftest() == 1);
    printf("ok %u\n", checks);
    return 0;
}
