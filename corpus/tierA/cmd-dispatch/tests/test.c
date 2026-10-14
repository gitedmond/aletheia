#include "program.h"
#include "native-check.h"
// @algorithm none
int main(void) {
    CHECK(fnv1a_32_local(NULL, 0) == UINT32_C(0x811c9dc5));
    CHECK(fnv1a_32_local((const uint8_t *)"a", 1) == UINT32_C(0xe40c292c));
    CHECK(sum8(NULL, 0) == 0);
    const uint8_t data[] = {255, 1, 2};
    CHECK(sum8(data, 3) == 2);
    CHECK(lookup_cmd("hash") != NULL);
    CHECK(lookup_cmd("sum") != NULL);
    CHECK(lookup_cmd("help") != NULL);
    CHECK(lookup_cmd("missing") == NULL);
    CHECK(dispatch("missing", 0, NULL) != 0);
    CHECK(run_command(0, NULL) != 0);
    command_input = (const uint8_t *)"a";
    command_length = 1;
    char *args[] = {"hash", NULL};
    CHECK(run_command(1, args) == 0);
    CHECK(dispatch("sum", 1, args) == 0);
    CHECK(cmd_help(0, NULL) == 0);
    printf("ok %u\n", checks);
    return 0;
}
