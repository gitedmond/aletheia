#include "program.h"
#include "native-check.h"
#include <string.h>
#include <stdlib.h>
int main(void) {
    uint8_t out[8] = {99,99,99,99,99,99,99,99};
    const uint8_t in[4] = {0,128,255,7};
    CHECK(my_memcpy(out + 1, in, 4) == out + 1);
    CHECK(out[0] == 99 && out[5] == 99 && memcmp(out + 1, in, 4) == 0);
    CHECK(my_memcpy(out, in, 0) == out && out[0] == 99);
    CHECK(my_memset(out, 0x1ab, 3) == out && out[0] == 0xab && out[2] == 0xab && out[3] == 255);
    CHECK(my_memcmp(in, in, 4) == 0 && my_memcmp(in, out, 4) < 0);
    CHECK(my_memcmp(out, in, 4) > 0 && my_memcmp(out, in, 0) == 0);
    void *p = xmalloc(0); CHECK(p != NULL); free(p);
    printf("ok %u\n", checks);
    return 0;
}
