#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
#include <stddef.h>
#include <stdint.h>
typedef struct {uint32_t state[5];uint64_t total;size_t used;uint8_t block[64];} sha1_t;
typedef struct {uint32_t state[8];uint64_t total;size_t used;uint8_t block[64];} sha256_t;
void sha1_init(sha1_t *);void sha1_update(sha1_t *,const uint8_t *,size_t);void sha1_final(sha1_t *,uint8_t *);void sha1_transform(sha1_t *,const uint8_t *);
void sha256_init(sha256_t *);void sha256_update(sha256_t *,const uint8_t *,size_t);void sha256_final(sha256_t *,uint8_t *);void sha256_transform(sha256_t *,const uint8_t *);void sha256_oneshot(const uint8_t *,size_t,uint8_t *);
#endif
