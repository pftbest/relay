#include <string.h>
#include "util.h"

void strncpy_s(char * volatile dst, const char * volatile src, size_t n) {
    strncpy(dst, src, n);
    dst[n - 1] = '\0';
}
