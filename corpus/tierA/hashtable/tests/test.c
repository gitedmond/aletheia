#include "program.h"
#include "native-check.h"
// @algorithm none
int main(void) {
    const uint8_t a[] = "a";
    CHECK(fnv1a_32(NULL, 0) == UINT32_C(0x811c9dc5));
    CHECK(fnv1_32(NULL, 0) == UINT32_C(0x811c9dc5));
    CHECK(fnv1a_32(a, 1) == UINT32_C(0xe40c292c));
    CHECK(fnv1_32(a, 1) == UINT32_C(0x050c5d7e));
    CHECK(fnv1a_32((const uint8_t *)"foobar", 6) == UINT32_C(0xbf9cf968));
    CHECK(djb2("") == UINT32_C(5381));
    CHECK(djb2("a") == UINT32_C(0x0002b606));
    CHECK(djb2_buf(NULL, 0) == UINT32_C(5381));
    CHECK(djb2_buf(a, 1) == UINT32_C(0x0002b606));
    CHECK(djb2a_buf(a, 1) == UINT32_C(0x0002b5c4));
    CHECK(djb2a_buf(NULL, 0) == UINT32_C(5381));
    const uint8_t binary[] = {'a', 0, 'b'};
    CHECK(djb2_buf(binary, 3) == UINT32_C(0x0b884fe8));
    CHECK(djb2((const char *)binary) == UINT32_C(0x0002b606));
    CHECK(ht_create(0, fnv1a_32) == NULL);
    CHECK(ht_create(4, NULL) == NULL);
    for (unsigned kind = 0; kind < 2; ++kind) {
        ht_t *table = ht_create(1, kind == 0 ? fnv1a_32 : djb2_buf);
        CHECK(table != NULL);
        CHECK(ht_insert(table, "one", 3) == 0);
        CHECK(ht_insert(table, "two", 7) == 0);
        CHECK(ht_insert(table, "", -4) == 0);
        int out = 42;
        CHECK(ht_lookup(table, "one", &out) == 1 && out == 3);
        CHECK(ht_lookup(table, "two", &out) == 1 && out == 7);
        CHECK(ht_lookup(table, "", &out) == 1 && out == -4);
        CHECK(ht_insert(table, "one", 9) == 0);
        CHECK(ht_lookup(table, "one", &out) == 1 && out == 9);
        CHECK(ht_lookup(table, "absent", &out) == 0 && out == 9);
        ht_destroy(table);
    }
    ht_destroy(NULL);
    printf("ok %u\n", checks);
    return 0;
}
