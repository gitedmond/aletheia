#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
uint32_t adler32_update(uint32_t adler, const uint8_t *buf, size_t len);
uint32_t adler32(const uint8_t *buf, size_t len);
uint16_t fletcher16(const uint8_t *buf, size_t len);
int sum_file(const char *path, uint32_t *out);
#endif
