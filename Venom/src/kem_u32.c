#include <stdlib.h>
#include <string.h>
#include "../../common/sha3/fips202.h"
#include "../../common/random/random.h"
#include "venom_u32_core.h"
#include "venom_macrify.h"
#include <stdio.h>
#include <time.h>

#define DITHER_DOMAIN_PK 0xA1
#define DITHER_DOMAIN_U  0xB1
#define DITHER_DOMAIN_V  0xC1

#define PK_PACKED_BYTES ((PARAMS_PK_LOGP * PARAMS_N * PARAMS_NBAR) / 8)
#define CT_C1_PACKED_BYTES ((PARAMS_U_LOGP * PARAMS_N * PARAMS_NBAR) / 8)
#define CT_C2_PACKED_BYTES ((PARAMS_V_LOGP * PARAMS_NBAR * PARAMS_NBAR) / 8)

#define SK_OFFSET_S 0
#define SK_OFFSET_PK (SK_OFFSET_S + CRYPTO_BYTES)
#define SK_OFFSET_SEEDS (SK_OFFSET_PK + CRYPTO_PUBLICKEYBYTES)
#define SK_OFFSET_PKH (SK_OFFSET_SEEDS + 32)

static inline uint32_t qmask_u32(void) { return (1u << PARAMS_LOGQ) - 1u; }
static inline uint32_t pmask_u32(unsigned logp) { return (1u << logp) - 1u; }
static int bench_verbose_enabled(void)
{
    const char *a = getenv("BENCH_VERBOSE");
    const char *b = getenv("DEBUG_BENCH");
    return ((a != NULL && strcmp(a, "1") == 0) || (b != NULL && strcmp(b, "1") == 0));
}
static void bench_log(const char *fn, const char *msg)
{
    if (!bench_verbose_enabled()) return;
    fprintf(stderr, "[bench-u32] level=%d fn=%s %s\n", PARAMS_N, fn, msg);
    fflush(stderr);
}
static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int8_t ct_verify_u32(const uint32_t *a, const uint32_t *b, size_t len)
{
    uint32_t r = 0;
    for (size_t i = 0; i < len; i++) r |= a[i] ^ b[i];
    return (r == 0) ? 0 : -1;
}

static int expand_dither_u32(uint32_t *d, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain, unsigned logp)
{
    unsigned shift = PARAMS_LOGQ - logp;
    uint32_t mask = (1u << shift) - 1u;
    uint8_t in[1 + BYTES_SEED_A + BYTES_SALT] = {0};
    uint8_t *buf = (uint8_t *)malloc(n * 4);
    if (!buf) return 1;
    in[0] = domain;
    memcpy(&in[1], seed, seedlen);
    shake(buf, n * 4, in, 1 + seedlen);
    for (size_t i = 0; i < n; i++) {
        uint32_t v = (uint32_t)buf[4*i] | ((uint32_t)buf[4*i+1] << 8) | ((uint32_t)buf[4*i+2] << 16) | ((uint32_t)buf[4*i+3] << 24);
        d[i] = v & mask;
    }
    clear_bytes(buf, n * 4);
    free(buf);
    return 0;
}

static uint32_t quantize_u32(uint32_t x, uint32_t d, unsigned logp)
{
    unsigned shift = PARAMS_LOGQ - logp;
    uint32_t z = (x & qmask_u32()) + (d & ((1u << shift) - 1u));
    z &= qmask_u32();
    z = (z + (1u << (shift - 1))) >> shift;
    return z & pmask_u32(logp);
}

static int quantize_dithered_u32(uint32_t *out, const uint32_t *in, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain, unsigned logp)
{
    uint32_t *d = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!d) return 1;
    if (expand_dither_u32(d, n, seed, seedlen, domain, logp) != 0) { free(d); return 1; }
    for (size_t i = 0; i < n; i++) out[i] = quantize_u32(in[i], d[i], logp);
    clear_bytes((uint8_t *)d, n * sizeof(uint32_t));
    free(d);
    return 0;
}

static int reconstruct_dithered_u32(uint32_t *normal, const uint32_t *split, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain, unsigned logp)
{
    uint32_t *d = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!d) return 1;
    if (expand_dither_u32(d, n, seed, seedlen, domain, logp) != 0) { free(d); return 1; }
    for (size_t i = 0; i < n; i++) {
        uint32_t r = (split[i] & pmask_u32(logp)) << (PARAMS_LOGQ - logp);
        normal[i] = (r - d[i]) & qmask_u32();
    }
    clear_bytes((uint8_t *)d, n * sizeof(uint32_t));
    free(d);
    return 0;
}

static void sample_from_seed(int32_t *S, const uint8_t *seedSE, uint8_t domain, unsigned eta)
{
    uint8_t in[1 + BYTES_SEED_SE];
    uint16_t *rnd = (uint16_t *)malloc((size_t)PARAMS_N * PARAMS_NBAR * sizeof(uint16_t));
    in[0] = domain;
    memcpy(&in[1], seedSE, BYTES_SEED_SE);
    shake((uint8_t *)rnd, (size_t)PARAMS_N * PARAMS_NBAR * sizeof(uint16_t), in, sizeof(in));
    for (size_t i = 0; i < (size_t)PARAMS_N * PARAMS_NBAR; i++) rnd[i] = LE_TO_UINT16(rnd[i]);
    venom_sample_n_u32(S, rnd, (size_t)PARAMS_N * PARAMS_NBAR, eta);
    clear_bytes((uint8_t *)rnd, (size_t)PARAMS_N * PARAMS_NBAR * sizeof(uint16_t));
    free(rnd);
}

int crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
{
    double t0 = now_s();
    bench_log("keygen", "start keygen");
    uint8_t *pk_seedA = &pk[0];
    uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t randomness[CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A];
    uint8_t *randomness_s = &randomness[0];
    uint8_t *randomness_seedSE = &randomness[CRYPTO_BYTES];
    uint8_t *randomness_z = &randomness[CRYPTO_BYTES + BYTES_SEED_SE];

    uint32_t *B_raw = calloc((size_t)PARAMS_N * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *B_split = calloc((size_t)PARAMS_N * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *E_zero = calloc((size_t)PARAMS_N * PARAMS_NBAR, sizeof(uint32_t));
    int32_t *S = calloc((size_t)PARAMS_N * PARAMS_NBAR, sizeof(int32_t));
    if (!B_raw || !B_split || !E_zero || !S) return 1;

    if (randombytes(randomness, sizeof(randomness)) != 0) return 1;
    shake(pk_seedA, BYTES_SEED_A, randomness_z, BYTES_SEED_A);
    sample_from_seed(S, randomness_seedSE, 0x5F, PARAMS_ETA_S);

    bench_log("keygen", "start keygen multiplication");
    if (!venom_mul_add_as_plus_e_u32(B_raw, S, E_zero, pk_seedA)) return 1;
    if (bench_verbose_enabled()) { fprintf(stderr, "[bench-u32] level=%d fn=keygen end keygen multiplication %.3fs\n", PARAMS_N, now_s() - t0); }
    if (quantize_dithered_u32(B_split, B_raw, (size_t)PARAMS_N * PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK, PARAMS_PK_LOGP) != 0) return 1;
    venom_pack_u32(pk_b, PK_PACKED_BYTES, B_split, (size_t)PARAMS_N * PARAMS_NBAR, PARAMS_PK_LOGP);

    memset(sk, 0, CRYPTO_SECRETKEYBYTES);
    memcpy(&sk[SK_OFFSET_S], randomness_s, CRYPTO_BYTES);
    memcpy(&sk[SK_OFFSET_PK], pk, CRYPTO_PUBLICKEYBYTES);
    memcpy(&sk[SK_OFFSET_SEEDS], randomness_seedSE, 32);
    shake(&sk[SK_OFFSET_PKH], BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);

    clear_bytes((uint8_t *)B_raw, (size_t)PARAMS_N * PARAMS_NBAR * sizeof(uint32_t));
    clear_bytes((uint8_t *)B_split, (size_t)PARAMS_N * PARAMS_NBAR * sizeof(uint32_t));
    clear_bytes((uint8_t *)S, (size_t)PARAMS_N * PARAMS_NBAR * sizeof(int32_t));
    free(B_raw); free(B_split); free(E_zero); free(S);
    if (bench_verbose_enabled()) { fprintf(stderr, "[bench-u32] level=%d fn=keygen end keygen total %.3fs\n", PARAMS_N, now_s() - t0); }
    return 0;
}

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    double t0 = now_s();
    bench_log("encaps", "start encaps");
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[CT_C1_PACKED_BYTES];
    uint8_t *salt = &ct[CRYPTO_CIPHERTEXTBYTES - BYTES_SALT];

    uint32_t *B_split = calloc((size_t)PARAMS_N * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *B_norm = calloc((size_t)PARAMS_N * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *Bp_raw = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(uint32_t));
    uint32_t *Bp_split = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(uint32_t));
    uint32_t *V_raw = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *C_split = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *C_enc = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *E_zero = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(uint32_t));
    uint32_t *E_zero_nbar = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    int32_t *Sp = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(int32_t));
    uint8_t *mu = calloc(BYTES_MU, 1);
    uint8_t rnd_mu_salt[BYTES_MU + BYTES_SALT];
    uint8_t G2in[BYTES_PKHASH + BYTES_MU + BYTES_SALT];
    uint8_t G2out[BYTES_SEED_SE + CRYPTO_BYTES];
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];

    if (!B_split||!B_norm||!Bp_raw||!Bp_split||!V_raw||!C_split||!C_enc||!E_zero||!E_zero_nbar||!Sp||!mu) return 1;

    shake(&G2in[0], BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);
    if (randombytes(rnd_mu_salt, BYTES_MU + BYTES_SALT) != 0) return 1;
    memcpy(mu, rnd_mu_salt, BYTES_MU);
    memcpy(&G2in[BYTES_PKHASH], mu, BYTES_MU);
    memcpy(&G2in[BYTES_PKHASH + BYTES_MU], rnd_mu_salt + BYTES_MU, BYTES_SALT);
    memcpy(salt, rnd_mu_salt + BYTES_MU, BYTES_SALT);

    shake(G2out, sizeof(G2out), G2in, sizeof(G2in));
    sample_from_seed(Sp, G2out, 0x96, PARAMS_ETA_R);

    bench_log("encaps", "start encaps multiplication-1");
    if (!venom_mul_add_sa_plus_e_u32(Bp_raw, Sp, E_zero, pk_seedA)) return 1;
    if (quantize_dithered_u32(Bp_split, Bp_raw, (size_t)PARAMS_NBAR * PARAMS_N, salt, BYTES_SALT, DITHER_DOMAIN_U, PARAMS_U_LOGP) != 0) return 1;
    venom_pack_u32(ct_c1, CT_C1_PACKED_BYTES, Bp_split, (size_t)PARAMS_NBAR * PARAMS_N, PARAMS_U_LOGP);

    venom_unpack_u32(B_split, (size_t)PARAMS_N * PARAMS_NBAR, pk_b, PK_PACKED_BYTES, PARAMS_PK_LOGP);
    if (reconstruct_dithered_u32(B_norm, B_split, (size_t)PARAMS_N * PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK, PARAMS_PK_LOGP) != 0) return 1;
    bench_log("encaps", "start encaps multiplication-2");
    venom_mul_add_sb_plus_e_u32(V_raw, B_norm, Sp, E_zero_nbar);

    venom_key_encode_u32(C_enc, mu);
    for (size_t i = 0; i < (size_t)PARAMS_NBAR * PARAMS_NBAR; i++) C_enc[i] = (C_enc[i] + V_raw[i]) & qmask_u32();
    if (quantize_dithered_u32(C_split, C_enc, (size_t)PARAMS_NBAR * PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V, PARAMS_V_LOGP) != 0) return 1;
    venom_pack_u32(ct_c2, CT_C2_PACKED_BYTES, C_split, (size_t)PARAMS_NBAR * PARAMS_NBAR, PARAMS_V_LOGP);

    memcpy(Fin, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(&Fin[CRYPTO_CIPHERTEXTBYTES], &G2out[BYTES_SEED_SE], CRYPTO_BYTES);
    shake(ss, CRYPTO_BYTES, Fin, sizeof(Fin));

    if (bench_verbose_enabled()) { fprintf(stderr, "[bench-u32] level=%d fn=encaps end encaps total %.3fs\n", PARAMS_N, now_s() - t0); }
    return 0;
}

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    double t0 = now_s();
    bench_log("decaps", "start decaps");
    const uint8_t *pk = &sk[SK_OFFSET_PK];
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    const uint8_t *seedS = &sk[SK_OFFSET_SEEDS];
    const uint8_t *sk_pkh = &sk[SK_OFFSET_PKH];

    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[CT_C1_PACKED_BYTES];
    const uint8_t *salt = &ct[CRYPTO_CIPHERTEXTBYTES - BYTES_SALT];

    uint32_t *B_split = calloc((size_t)PARAMS_N * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *B_norm = calloc((size_t)PARAMS_N * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *Bp_split = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(uint32_t));
    uint32_t *Bp_norm = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(uint32_t));
    uint32_t *BBp_raw = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(uint32_t));
    uint32_t *BBp_split = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(uint32_t));
    uint32_t *W = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *C_split = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *C_norm = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *CC = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *CC_split = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    uint32_t *E_zero = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(uint32_t));
    uint32_t *E_zero_nbar = calloc((size_t)PARAMS_NBAR * PARAMS_NBAR, sizeof(uint32_t));
    int32_t *S = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(int32_t));
    int32_t *Sp = calloc((size_t)PARAMS_NBAR * PARAMS_N, sizeof(int32_t));
    uint8_t *muprime = calloc(BYTES_MU, 1);
    uint8_t *G2in = calloc(BYTES_PKHASH + BYTES_MU + BYTES_SALT, 1);
    uint8_t *G2out = calloc(BYTES_SEED_SE + CRYPTO_BYTES, 1);
    uint8_t *Fin = calloc(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES, 1);
    if (!B_split||!B_norm||!Bp_split||!Bp_norm||!BBp_raw||!BBp_split||!W||!C_split||!C_norm||!CC||!CC_split||!E_zero||!E_zero_nbar||!S||!Sp||!muprime||!G2in||!G2out||!Fin) return 1;

    sample_from_seed(S, seedS, 0x5F, PARAMS_ETA_S);

    venom_unpack_u32(Bp_split, (size_t)PARAMS_NBAR * PARAMS_N, ct_c1, CT_C1_PACKED_BYTES, PARAMS_U_LOGP);
    venom_unpack_u32(C_split, (size_t)PARAMS_NBAR * PARAMS_NBAR, ct_c2, CT_C2_PACKED_BYTES, PARAMS_V_LOGP);
    if (reconstruct_dithered_u32(Bp_norm, Bp_split, (size_t)PARAMS_NBAR * PARAMS_N, salt, BYTES_SALT, DITHER_DOMAIN_U, PARAMS_U_LOGP) != 0) return 1;
    if (reconstruct_dithered_u32(C_norm, C_split, (size_t)PARAMS_NBAR * PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V, PARAMS_V_LOGP) != 0) return 1;

    bench_log("decaps", "start decaps multiplication-1");
    venom_mul_bs_u32(W, Bp_norm, S);
    for (size_t i = 0; i < (size_t)PARAMS_NBAR * PARAMS_NBAR; i++) W[i] = (C_norm[i] - W[i]) & qmask_u32();
    venom_key_decode_u32(muprime, W);

    memcpy(G2in, sk_pkh, BYTES_PKHASH);
    memcpy(&G2in[BYTES_PKHASH], muprime, BYTES_MU);
    memcpy(&G2in[BYTES_PKHASH + BYTES_MU], salt, BYTES_SALT);
    shake(G2out, BYTES_SEED_SE + CRYPTO_BYTES, G2in, BYTES_PKHASH + BYTES_MU + BYTES_SALT);

    sample_from_seed(Sp, G2out, 0x96, PARAMS_ETA_R);
    bench_log("decaps", "start decaps reencryption-1");
    if (!venom_mul_add_sa_plus_e_u32(BBp_raw, Sp, E_zero, pk_seedA)) return 1;
    if (quantize_dithered_u32(BBp_split, BBp_raw, (size_t)PARAMS_NBAR * PARAMS_N, salt, BYTES_SALT, DITHER_DOMAIN_U, PARAMS_U_LOGP) != 0) return 1;

    venom_unpack_u32(B_split, (size_t)PARAMS_N * PARAMS_NBAR, pk_b, PK_PACKED_BYTES, PARAMS_PK_LOGP);
    if (reconstruct_dithered_u32(B_norm, B_split, (size_t)PARAMS_N * PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK, PARAMS_PK_LOGP) != 0) return 1;
    bench_log("decaps", "start decaps reencryption-2");
    venom_mul_add_sb_plus_e_u32(CC, B_norm, Sp, E_zero_nbar);
    venom_key_encode_u32(W, muprime);
    for (size_t i = 0; i < (size_t)PARAMS_NBAR * PARAMS_NBAR; i++) CC[i] = (CC[i] + W[i]) & qmask_u32();
    if (quantize_dithered_u32(CC_split, CC, (size_t)PARAMS_NBAR * PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V, PARAMS_V_LOGP) != 0) return 1;

    int8_t selector = ct_verify_u32(Bp_split, BBp_split, (size_t)PARAMS_NBAR * PARAMS_N) | ct_verify_u32(C_split, CC_split, (size_t)PARAMS_NBAR * PARAMS_NBAR);
    const uint8_t *k = (selector == 0) ? &G2out[BYTES_SEED_SE] : &sk[SK_OFFSET_S];

    memcpy(Fin, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(&Fin[CRYPTO_CIPHERTEXTBYTES], k, CRYPTO_BYTES);
    shake(ss, CRYPTO_BYTES, Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);
    if (bench_verbose_enabled()) { fprintf(stderr, "[bench-u32] level=%d fn=decaps end decaps total %.3fs\n", PARAMS_N, now_s() - t0); }
    return 0;
}
