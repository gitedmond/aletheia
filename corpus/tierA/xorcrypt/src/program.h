#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
#include <stddef.h>
#include <stdint.h>
typedef struct {uint8_t s[256], i, j;} rc4_t;
void xor_crypt(uint8_t *, size_t, const uint8_t *, size_t);
int rc4_init(rc4_t *, const uint8_t *, size_t);
void rc4_crypt(rc4_t *, uint8_t *, size_t);
#endif
