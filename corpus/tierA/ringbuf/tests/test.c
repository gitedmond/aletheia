#include "program.h"
#include "native-check.h"
#include <string.h>
#include <stdlib.h>
int main(void) {
    ring_t r; uint8_t storage[2], out = 99;
    CHECK(rb_init(&r, storage, 0) == -1);
    CHECK(rb_init(&r, storage, 2) == 0);
    CHECK(rb_count(&r) == 0 && rb_pop(&r, &out) == 0 && out == 99);
    CHECK(rb_push(&r, 7) == 1 && rb_push(&r, 9) == 1 && rb_push(&r, 3) == 0);
    CHECK(rb_count(&r) == 2 && rb_pop(&r, &out) == 1 && out == 7);
    CHECK(rb_push(&r, 11) == 1 && rb_pop(&r, &out) == 1 && out == 9);
    CHECK(rb_pop(&r, &out) == 1 && out == 11 && rb_count(&r) == 0);
    printf("ok %u\n", checks);
    return 0;
}
