#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
#include <stddef.h>
#include <stdint.h>
typedef struct {uint8_t *data; size_t capacity, head, tail, count;} ring_t;
int rb_init(ring_t *, uint8_t *, size_t);
int rb_push(ring_t *, uint8_t);
int rb_pop(ring_t *, uint8_t *);
size_t rb_count(const ring_t *);
#endif
