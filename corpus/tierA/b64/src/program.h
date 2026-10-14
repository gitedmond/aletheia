#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
size_t b64_encode(const uint8_t *in, size_t len, char *out);
size_t b64_encode_url(const uint8_t *in, size_t len, char *out);
ptrdiff_t b64_decode(const char *in, size_t len, uint8_t *out);
size_t b64_encoded_len(size_t len);
#endif
