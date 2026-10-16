#include "program.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
// @algorithm none
// @category util.init
ALETHEIA_TARGET int rb_init(ring_t *r, uint8_t *storage, size_t capacity) {
    if (r == NULL || storage == NULL || capacity == 0) return -1;
    r->data = storage; r->capacity = capacity; r->head = 0; r->tail = 0; r->count = 0;
    return 0;
}
// @algorithm none
// @category container.ringbuffer.push
ALETHEIA_TARGET int rb_push(ring_t *r, uint8_t value) {
    if (r->count == r->capacity) return 0;
    r->data[r->tail] = value;
    r->tail = (r->tail + 1) % r->capacity; ++r->count;
    return 1;
}
// @algorithm none
// @category container.ringbuffer.pop
ALETHEIA_TARGET int rb_pop(ring_t *r, uint8_t *out) {
    if (r->count == 0 || out == NULL) return 0;
    *out = r->data[r->head]; r->head = (r->head + 1) % r->capacity; --r->count;
    return 1;
}
// @algorithm none
// @category util.other
ALETHEIA_TARGET size_t rb_count(const ring_t *r) { return r->count; }
