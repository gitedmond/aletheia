#include "program.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
// @algorithm none
// @category util.init
ALETHEIA_TARGET void lexer_init(lexer_t *lexer, const char *text) {
    lexer->input = text; lexer->position = 0; lexer->start = 0; lexer->length = 0;
}
// @algorithm none
// @category string.other
ALETHEIA_TARGET int classify_char(unsigned char c) {
    if (c == 0) return 0;
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') return 1;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') return 2;
    if (c >= '0' && c <= '9') return 3;
    return 4;
}
// @algorithm none
// @category control.state_machine
ALETHEIA_TARGET int lex_next(lexer_t *lexer) {
    const char *text = lexer->input;
    while (classify_char((unsigned char)text[lexer->position]) == 1) ++lexer->position;
    lexer->start = lexer->position;
    int token = classify_char((unsigned char)text[lexer->position]);
    if (token == 0) {lexer->length = 0; return 0;}
    ++lexer->position;
    if (token == 2 || token == 3) {
        for (;;) {
            int next = classify_char((unsigned char)text[lexer->position]);
            if (next != token && !(token == 2 && next == 3)) break;
            ++lexer->position;
        }
    }
    lexer->length = lexer->position - lexer->start;
    return token;
}
