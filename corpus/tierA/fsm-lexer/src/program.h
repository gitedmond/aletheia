#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
#include <stddef.h>
#include <stdint.h>
typedef struct {const char *input; size_t position, start, length;} lexer_t;
void lexer_init(lexer_t *, const char *);
int lex_next(lexer_t *);
int classify_char(unsigned char);
#endif
