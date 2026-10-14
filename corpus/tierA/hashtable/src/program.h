#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
typedef uint32_t (*hash_fn_t)(const uint8_t *, size_t);
typedef struct ht ht_t;
uint32_t fnv1a_32(const uint8_t *buf, size_t len);
uint32_t fnv1_32(const uint8_t *buf, size_t len);
uint32_t djb2(const char *s);
uint32_t djb2_buf(const uint8_t *buf, size_t len);
uint32_t djb2a_buf(const uint8_t *buf, size_t len);
ht_t *ht_create(size_t buckets, hash_fn_t fn);
int ht_insert(ht_t *t, const char *key, int value);
int ht_lookup(ht_t *t, const char *key, int *out);
void ht_destroy(ht_t *t);
#endif
