#include <stdio.h>
#include <stdlib.h>

#include "../src/api_frost128.h"
enum { PK128 = CRYPTO_PUBLICKEYBYTES, CT128 = CRYPTO_CIPHERTEXTBYTES, SK128 = CRYPTO_SECRETKEYBYTES, SS128 = CRYPTO_BYTES };
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_CIPHERTEXTBYTES
#undef CRYPTO_ALGNAME
#include "../src/api_frost192.h"
enum { PK192 = CRYPTO_PUBLICKEYBYTES, CT192 = CRYPTO_CIPHERTEXTBYTES, SK192 = CRYPTO_SECRETKEYBYTES, SS192 = CRYPTO_BYTES };
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_CIPHERTEXTBYTES
#undef CRYPTO_ALGNAME
#include "../src/api_frost256.h"
enum { PK256 = CRYPTO_PUBLICKEYBYTES, CT256 = CRYPTO_CIPHERTEXTBYTES, SK256 = CRYPTO_SECRETKEYBYTES, SS256 = CRYPTO_BYTES };
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_CIPHERTEXTBYTES
#undef CRYPTO_ALGNAME
#include "../src/api_frost384.h"
enum { PK384 = CRYPTO_PUBLICKEYBYTES, CT384 = CRYPTO_CIPHERTEXTBYTES, SK384 = CRYPTO_SECRETKEYBYTES, SS384 = CRYPTO_BYTES };
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_CIPHERTEXTBYTES
#undef CRYPTO_ALGNAME
#include "../src/api_frost512.h"
enum { PK512 = CRYPTO_PUBLICKEYBYTES, CT512 = CRYPTO_CIPHERTEXTBYTES, SK512 = CRYPTO_SECRETKEYBYTES, SS512 = CRYPTO_BYTES };

typedef struct {
    const char *name;
    unsigned n, m, ell, qbits, eta_s, eta_r, b_msg, t_pk, t_u, t_v;
    unsigned macro_pk, macro_ct, macro_sk, macro_ss;
    unsigned paper_pk, paper_ct, paper_sk, paper_ss;
} profile_t;

static unsigned ceil_log2_u(unsigned x)
{
    unsigned bits = 0;
    unsigned v = x - 1u;
    while (v != 0u) {
        bits++;
        v >>= 1;
    }
    return bits;
}

static unsigned calc_pk(const profile_t *p) { return 32u + p->m * p->ell * p->t_pk / 8u; }
static unsigned calc_ct(const profile_t *p) { return 32u + p->n * p->ell * p->t_u / 8u + p->ell * p->ell * p->t_v / 8u; }
static unsigned calc_skpke(const profile_t *p) { return p->n * p->ell * ceil_log2_u(2u * p->eta_s + 1u) / 8u; }
static unsigned calc_sk(const profile_t *p) { return calc_skpke(p) + calc_pk(p) + 64u; }
static unsigned calc_ss(const profile_t *p) { return p->b_msg * p->ell * p->ell / 8u; }

int main(void)
{
    const profile_t profiles[] = {
        { "MAMBA-Frost-128", 512, 512, 8, 15, 2, 2, 2, 10, 10, 8, PK128, CT128, SK128, SS128, 5152, 5216, 6752, 16 },
        { "MAMBA-Frost-192", 872, 872, 8, 16, 1, 1, 3, 11, 11, 8, PK192, CT192, SK192, SS192, 9624, 9688, 11432, 24 },
        { "MAMBA-Frost-256", 1280, 1280, 8, 16, 1, 1, 4, 13, 12, 7, PK256, CT256, SK256, SS256, 16672, 15448, 19296, 32 },
        { "MAMBA-Frost-384", 2176, 2176, 8, 18, 3, 3, 6, 16, 15, 13, PK384, CT384, SK384, SS384, 0, 0, 0, 0 },
        { "MAMBA-Frost-512", 3072, 3072, 8, 20, 4, 4, 8, 18, 18, 11, PK512, CT512, SK512, SS512, 0, 0, 0, 0 },
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof(profiles)/sizeof(profiles[0]); i++) {
        const profile_t *p = &profiles[i];
        unsigned epk = calc_pk(p), ect = calc_ct(p), eskpke = calc_skpke(p), esk = calc_sk(p), ess = calc_ss(p);
        printf("%s n=%u m=%u ell=%u q=2^%u eta_s=%u eta_r=%u b_msg=%u t_pk=%u t_u=%u t_v=%u | formula pk=%u ct=%u sk_PKE=%u sk_KEM=%u ss=%u | macros pk=%u ct=%u sk_KEM=%u ss=%u\n",
               p->name, p->n, p->m, p->ell, p->qbits, p->eta_s, p->eta_r, p->b_msg, p->t_pk, p->t_u, p->t_v,
               epk, ect, eskpke, esk, ess, p->macro_pk, p->macro_ct, p->macro_sk, p->macro_ss);
        if (p->paper_pk && (epk != p->paper_pk || ect != p->paper_ct || esk != p->paper_sk || ess != p->paper_ss)) ok = 0;
        if (p->macro_pk != epk || p->macro_ct != ect || p->macro_sk != esk || p->macro_ss != ess) ok = 0;
    }
    if (!ok) {
        fprintf(stderr, "Frost size test FAILED\n");
        return EXIT_FAILURE;
    }
    puts("Frost size test PASSED");
    return EXIT_SUCCESS;
}
