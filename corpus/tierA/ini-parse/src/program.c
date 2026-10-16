#include "program.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
// @algorithm djb2/add
// @category hash.noncrypto.djb2
static uint32_t key_hash(const char *key) {
    uint32_t value = 5381;
    for (size_t i = 0; key[i] != 0; ++i) value = value * 33 + (unsigned char)key[i];
    return value;
}
// @algorithm none
// @category string.other
ALETHEIA_TARGET char *str_trim(char *text) {
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') ++text;
    size_t length = strlen(text);
    while (length != 0 && (text[length-1] == ' ' || text[length-1] == '\t' || text[length-1] == '\r' || text[length-1] == '\n')) text[--length] = 0;
    return text;
}
// @algorithm none
// @category parse.ini
ALETHEIA_TARGET int ini_parse_line(ini_t *table, char *line) {
    char *key = str_trim(line);
    if (*key == 0 || *key == '#' || *key == ';' || *key == '[') return 0;
    char *equal = strchr(key, '='); if (equal == NULL) return -1;
    *equal = 0; key = str_trim(key); char *value = str_trim(equal + 1);
    if (*key == 0) return -1;
    size_t slot = key_hash(key) % 32;
    for (size_t n = 0; n < 32; ++n, slot = (slot+1) % 32) {
        ini_entry *entry = &table->entries[slot];
        if (entry->key != NULL && strcmp(entry->key, key) != 0) continue;
        char *new_key = malloc(strlen(key)+1), *new_value = malloc(strlen(value)+1);
        if (new_key == NULL || new_value == NULL) {free(new_key); free(new_value); return -1;}
        memcpy(new_key, key, strlen(key)+1); memcpy(new_value, value, strlen(value)+1);
        free(entry->key); free(entry->value); entry->key = new_key; entry->value = new_value;
        return 1;
    }
    return -1;
}
// @algorithm none
// @category container.hashtable.lookup
ALETHEIA_TARGET const char *ini_get(const ini_t *table, const char *key) {
    size_t slot = key_hash(key) % 32;
    for (size_t n = 0; n < 32; ++n, slot = (slot+1) % 32) {
        const ini_entry *entry = &table->entries[slot];
        if (entry->key == NULL) return NULL;
        if (strcmp(entry->key, key) == 0) return entry->value;
    }
    return NULL;
}
// @algorithm none
// @category util.cleanup
ALETHEIA_TARGET void ini_free(ini_t *table) {
    for (size_t i = 0; i < 32; ++i) {free(table->entries[i].key); free(table->entries[i].value); table->entries[i].key = NULL; table->entries[i].value = NULL;}
}
