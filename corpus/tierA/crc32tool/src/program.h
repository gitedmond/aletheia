#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
uint32_t crc32_update(uint32_t crc, const uint8_t *buf, size_t len);
uint32_t crc32_bitwise(const uint8_t *buf, size_t len);
uint32_t jamcrc(const uint8_t *buf, size_t len);
void crc32_table_init(void);
uint32_t crc32_update_rt(uint32_t crc, const uint8_t *buf, size_t len);
int crc32_selftest(void);
void hex_print32(uint32_t v);
#endif
