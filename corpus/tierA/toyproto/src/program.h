#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
#include <stddef.h>
#include <stdint.h>
size_t varint_put(uint64_t, uint8_t *);
size_t varint_get(const uint8_t *, size_t, uint64_t *);
size_t proto_encode(uint8_t, const uint8_t *, size_t, uint8_t *, size_t);
int proto_decode(const uint8_t *, size_t, uint8_t *, uint8_t *, size_t *);
uint32_t proto_handshake(uint32_t);
#endif
