#include "drng.h"
#include <stddef.h>

extern DRNG_ctx drng_algorithm;

int randombytes(unsigned char *x, unsigned long long xlen)
{
    if (x == NULL) {
        return -1;
    }
    return get_random_number(&drng_algorithm, x, xlen * 8ULL);
}
