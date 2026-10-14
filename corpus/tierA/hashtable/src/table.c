#include "program.h"
#include <stdlib.h>
#include <string.h>
typedef struct entry {
    char *key;
    int value;
    struct entry *next;
} entry_t;
struct ht {
    size_t buckets;
    hash_fn_t fn;
    entry_t **entries;
};
// @algorithm none
ALETHEIA_TARGET ht_t *ht_create(size_t buckets, hash_fn_t fn) {
    /* These are the only admitted callbacks, matching the indirect annotations. */
    if (buckets == 0 || buckets > SIZE_MAX / sizeof(entry_t *)
        || (fn != fnv1a_32 && fn != djb2_buf)) return NULL;
    ht_t *table = calloc(1, sizeof *table);
    if (table == NULL) return NULL;
    table->entries = calloc(buckets, sizeof *table->entries);
    if (table->entries == NULL) { free(table); return NULL; }
    table->buckets = buckets;
    table->fn = fn;
    return table;
}
// @algorithm none
// @indirect-targets fnv1a_32,djb2_buf
ALETHEIA_TARGET int ht_insert(ht_t *t, const char *key, int value) {
    size_t length = strlen(key);
    size_t index = t->fn((const uint8_t *)key, length) % t->buckets;
    for (entry_t *entry = t->entries[index]; entry; entry = entry->next) {
        if (strcmp(entry->key, key) == 0) { entry->value = value; return 0; }
    }
    entry_t *entry = malloc(sizeof *entry);
    if (entry == NULL) return -1;
    entry->key = malloc(length + 1);
    if (entry->key == NULL) { free(entry); return -1; }
    memcpy(entry->key, key, length + 1);
    entry->value = value;
    entry->next = t->entries[index];
    t->entries[index] = entry;
    return 0;
}
// @algorithm none
// @indirect-targets fnv1a_32,djb2_buf
ALETHEIA_TARGET int ht_lookup(ht_t *t, const char *key, int *out) {
    size_t index = t->fn((const uint8_t *)key, strlen(key)) % t->buckets;
    for (entry_t *entry = t->entries[index]; entry; entry = entry->next) {
        if (strcmp(entry->key, key) == 0) { *out = entry->value; return 1; }
    }
    return 0;
}
// @algorithm none
ALETHEIA_TARGET void ht_destroy(ht_t *t) {
    if (t == NULL) return;
    for (size_t i = 0; i < t->buckets; ++i) {
        entry_t *entry = t->entries[i];
        while (entry) {
            entry_t *next = entry->next;
            free(entry->key);
            free(entry);
            entry = next;
        }
    }
    free(t->entries);
    free(t);
}
