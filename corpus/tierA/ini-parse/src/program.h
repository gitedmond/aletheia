#ifndef PROGRAM_H
#define PROGRAM_H
#include "aletheia.h"
#include <stddef.h>
#include <stdint.h>
typedef struct {char *key, *value;} ini_entry;
typedef struct {ini_entry entries[32];} ini_t;
int ini_parse_line(ini_t *, char *);
char *str_trim(char *);
const char *ini_get(const ini_t *, const char *);
void ini_free(ini_t *);
#endif
