#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
#include <stddef.h>
#include <stdint.h>
void *my_memcpy(void *, const void *, size_t);
void *my_memset(void *, int, size_t);
int my_memcmp(const void *, const void *, size_t);
void *xmalloc(size_t);
#endif
