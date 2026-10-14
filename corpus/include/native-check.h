#ifndef NATIVE_CHECK_H
#define NATIVE_CHECK_H
#include <stdio.h>
static unsigned checks;
/* These checks remain active with -DNDEBUG. */
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "error at %d\n", __LINE__); return 1; } } while (0)
#endif
