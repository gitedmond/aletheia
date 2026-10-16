/* Original MIT fixture generator: inspect the pinned glibc C-locale tables. */
#define _DEFAULT_SOURCE
#include <ctype.h>
#include <gnu/libc-version.h>
#include <locale.h>
#include <stdio.h>

int main(void) {
    if (setlocale(LC_ALL, "C") == NULL) return 1;
    const unsigned short *b = *__ctype_b_loc();
    const int *lower = *__ctype_tolower_loc(), *upper = *__ctype_toupper_loc();
    printf("{\"schema_version\":\"1.0\",\"locale\":\"C\",\"glibc_version\":\"%s\","
           "\"index_min\":-128,\"class_bits\":{\"upper\":%u,\"lower\":%u,\"alpha\":%u,"
           "\"digit\":%u,\"xdigit\":%u,\"space\":%u,\"print\":%u,\"graph\":%u,"
           "\"blank\":%u,\"cntrl\":%u,\"punct\":%u,\"alnum\":%u},\"b\":[",
           gnu_get_libc_version(), (unsigned)_ISupper, (unsigned)_ISlower, (unsigned)_ISalpha,
           (unsigned)_ISdigit, (unsigned)_ISxdigit, (unsigned)_ISspace, (unsigned)_ISprint,
           (unsigned)_ISgraph, (unsigned)_ISblank, (unsigned)_IScntrl, (unsigned)_ISpunct,
           (unsigned)_ISalnum);
    for (int i = -128; i < 256; ++i) printf("%s%u", i == -128 ? "" : ",", (unsigned)b[i]);
    printf("],\"tolower\":[");
    for (int i = -128; i < 256; ++i) printf("%s%d", i == -128 ? "" : ",", lower[i]);
    printf("],\"toupper\":[");
    for (int i = -128; i < 256; ++i) printf("%s%d", i == -128 ? "" : ",", upper[i]);
    puts("]}");
    return 0;
}
