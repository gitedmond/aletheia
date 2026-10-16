#include "program.h"
#include "native-check.h"
#include <string.h>
#include <stdlib.h>
int main(void) {
    ini_t table = {0}; char a[] = " key = value ", b[] = "key=changed", c[] = "# ignored", d[] = "invalid", e[] = " =x";
    CHECK(ini_parse_line(&table, a) == 1 && strcmp(ini_get(&table, "key"), "value") == 0);
    CHECK(ini_parse_line(&table, b) == 1 && strcmp(ini_get(&table, "key"), "changed") == 0);
    CHECK(ini_parse_line(&table, c) == 0 && ini_parse_line(&table, d) == -1 && ini_parse_line(&table, e) == -1);
    CHECK(ini_get(&table, "missing") == NULL);
    char spaces[] = " \t "; CHECK(*str_trim(spaces) == 0);
    ini_free(&table); CHECK(ini_get(&table, "key") == NULL); ini_free(&table);
    printf("ok %u\n", checks);
    return 0;
}
