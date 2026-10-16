#include "program.h"
#include "native-check.h"
#include <string.h>
#include <stdlib.h>
int main(void) {
    lexer_t lexer; lexer_init(&lexer, "  item_2 123+z");
    CHECK(lex_next(&lexer) == 2 && lexer.start == 2 && lexer.length == 6);
    CHECK(lex_next(&lexer) == 3 && lexer.length == 3);
    CHECK(lex_next(&lexer) == 4 && lexer.length == 1);
    CHECK(lex_next(&lexer) == 2 && lexer.length == 1);
    CHECK(lex_next(&lexer) == 0 && lexer.length == 0);
    CHECK(classify_char(255) == 4 && classify_char(0) == 0);
    lexer_init(&lexer, ""); CHECK(lex_next(&lexer) == 0);
    printf("ok %u\n", checks);
    return 0;
}
