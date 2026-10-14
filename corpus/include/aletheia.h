#ifndef ALETHEIA_H
#define ALETHEIA_H
#include <stddef.h>
#include <stdint.h>
#define ALETHEIA_TARGET __attribute__((noinline))
/* path NULL or "-" selects stdin; caller frees the returned, NUL-terminated buffer. */
int read_input(const char *path, uint8_t **out, size_t *length);
#endif
