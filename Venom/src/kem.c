/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: Key Encapsulation Mechanism (KEM) based on Frodo
*********************************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "../../common/sha3/fips202.h"
#include "../../common/random/random.h"
#ifdef PROFILE_ALL_LEVELS
#include <stdio.h>
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static inline unsigned long long prof_now_cycles(void) { return __rdtsc(); }
#else
#include <time.h>
static inline unsigned long long prof_now_cycles(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}
#endif
static int prof_all_enabled(void)
{
    const char *p = getenv("PROFILE_ALL_LEVELS");
    return (p != NULL && strcmp(p, "1") == 0);
}
#define PROF_DECL() unsigned long long __p_total=0,__p_t0=0
#define PROF_BEGIN() do { if (prof_all_enabled()) __p_total = prof_now_cycles(); } while (0)
#define PROF_MARK(acc) do { if (prof_all_enabled()) { __p_t0 = prof_now_cycles(); } } while (0)
#define PROF_ADD(acc) do { if (prof_all_enabled()) { acc += prof_now_cycles() - __p_t0; } } while (0)
#define PROF_END(total) do { if (prof_all_enabled()) { total = prof_now_cycles() - __p_total; } } while (0)
#else
#define PROF_DECL()
#define PROF_BEGIN()
#define PROF_MARK(acc)
#define PROF_ADD(acc)
#define PROF_END(total)
#endif

#ifdef DO_VALGRIND_CHECK
#include <valgrind/memcheck.h>
#endif

#define DITHER_DOMAIN_PK 0xA1
#define DITHER_DOMAIN_U  0xB1
#define DITHER_DOMAIN_V  0xC1

#define PK_PACKED_BYTES ((PARAMS_PK_LOGP * PARAMS_N * PARAMS_NBAR) / 8)
#define CT_C1_PACKED_BYTES ((PARAMS_U_LOGP * PARAMS_N * PARAMS_NBAR) / 8)
#define CT_C2_PACKED_BYTES ((PARAMS_V_LOGP * PARAMS_NBAR * PARAMS_NBAR) / 8)
#define SK_OFFSET_S 0
#define SK_OFFSET_PK (SK_OFFSET_S + CRYPTO_BYTES)
#define SK_OFFSET_SEEDSE (SK_OFFSET_PK + CRYPTO_PUBLICKEYBYTES)
#define SK_OFFSET_PKH (SK_OFFSET_SEEDSE + BYTES_SEED_SE)

static inline uint16_t frodo_q_mask_local(void)
{
    return (uint16_t)((1u << PARAMS_LOGQ) - 1u);
}

static inline uint16_t frodo_p_mask_local(unsigned int logp)
{
    return (uint16_t)((1u << logp) - 1u);
}

static inline uint16_t frodo_reconstruct_local(uint16_t x, unsigned int logp)
{
    return (uint16_t)((x & frodo_p_mask_local(logp)) << (PARAMS_LOGQ - logp));
}

static inline uint16_t frodo_quantize_local(uint16_t x, uint16_t d, unsigned int logp)
{
    const unsigned int shift = PARAMS_LOGQ - logp;
    const uint32_t qmask = frodo_q_mask_local();
    uint32_t z = ((uint32_t)x & qmask) + ((uint32_t)d & ((1u << shift) - 1u));
    z &= qmask;
    z = (z + (1u << (shift - 1))) >> shift;
    return (uint16_t)(z & frodo_p_mask_local(logp));
}

static int frodo_expand_dither_local(uint16_t *d, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain, unsigned int logp)
{
    const unsigned int shift = PARAMS_LOGQ - logp;
    const uint16_t mask = (uint16_t)((1u << shift) - 1u);
    uint8_t in[1 + BYTES_SEED_A + BYTES_SALT] = {0};

    in[0] = domain;
    memcpy(&in[1], seed, seedlen);
    shake((uint8_t *)d, n * sizeof(uint16_t), in, 1 + seedlen);
    for (size_t i = 0; i < n; i++) {
        d[i] = LE_TO_UINT16(d[i]) & mask;
    }
    return 0;
}

static int frodo_quantize_dithered_local(uint16_t *out, const uint16_t *in, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain, unsigned int logp)
{
    uint16_t *d = (uint16_t *)malloc(n * sizeof(uint16_t));

    if (d == NULL) {
        return 1;
    }
    if (frodo_expand_dither_local(d, n, seed, seedlen, domain, logp) != 0) {
        clear_bytes((uint8_t *)d, n * sizeof(uint16_t));
        free(d);
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = frodo_quantize_local(in[i], d[i], logp);
    }
    clear_bytes((uint8_t *)d, n * sizeof(uint16_t));
    free(d);
    return 0;
}

static int frodo_reconstruct_dithered_local(uint16_t *normal, const uint16_t *split, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain, unsigned int logp)
{
    uint16_t *d = (uint16_t *)malloc(n * sizeof(uint16_t));

    if (d == NULL) {
        return 1;
    }
    if (frodo_expand_dither_local(d, n, seed, seedlen, domain, logp) != 0) {
        clear_bytes((uint8_t *)d, n * sizeof(uint16_t));
        free(d);
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        normal[i] = (uint16_t)((frodo_reconstruct_local(split[i], logp) - d[i]) & frodo_q_mask_local());
    }
    clear_bytes((uint8_t *)d, n * sizeof(uint16_t));
    free(d);
    return 0;
}

int crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
{ // FrodoKEM's key generation with public dithered quantization
    PROF_DECL();
    unsigned long long c_rand = 0, c_seedexp = 0, c_cbd = 0, c_as = 0, c_quant = 0, c_pack = 0, c_hash = 0, c_total = 0;
    PROF_BEGIN();
    uint8_t *pk_seedA = &pk[0];
    uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *sk_s = &sk[SK_OFFSET_S];
    uint8_t *sk_pk = &sk[SK_OFFSET_PK];
    uint8_t *sk_seedSE = &sk[SK_OFFSET_SEEDSE];
    uint8_t *sk_pkh = &sk[SK_OFFSET_PKH];
    uint16_t B_raw[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t B_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t S[PARAMS_N*PARAMS_NBAR] = {0};                          // contains secret data
    uint16_t E_zero[PARAMS_N*PARAMS_NBAR] = {0};
    uint8_t randomness[CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A]; // contains secret data via randomness_s and randomness_seedSE
    uint8_t *randomness_s = &randomness[0];                          // contains secret data
    uint8_t *randomness_seedSE = &randomness[CRYPTO_BYTES];          // contains secret data
    uint8_t *randomness_z = &randomness[CRYPTO_BYTES + BYTES_SEED_SE];
    uint8_t shake_input_seedSE[1 + BYTES_SEED_SE];                   // contains secret data

    PROF_MARK(c_rand);
    if (randombytes(randomness, CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A) != 0)
        return 1;
    PROF_ADD(c_rand);
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_UNDEFINED(randomness, CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A);
#endif
    PROF_MARK(c_seedexp);
    shake(pk_seedA, BYTES_SEED_A, randomness_z, BYTES_SEED_A);

    shake_input_seedSE[0] = 0x5F;
    memcpy(&shake_input_seedSE[1], randomness_seedSE, BYTES_SEED_SE);
    shake((uint8_t*)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + BYTES_SEED_SE);
    PROF_ADD(c_seedexp);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        S[i] = LE_TO_UINT16(S[i]);
    }
    PROF_MARK(c_cbd);
    frodo_sample_n(S, PARAMS_N*PARAMS_NBAR);
    PROF_ADD(c_cbd);
    PROF_MARK(c_as);
    frodo_mul_add_as_plus_e(B_raw, S, E_zero, pk_seedA);
    PROF_ADD(c_as);
    PROF_MARK(c_quant);
    if (frodo_quantize_dithered_local(B_split, B_raw, PARAMS_N*PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK, PARAMS_PK_LOGP) != 0) {
        clear_bytes((uint8_t *)B_raw, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
        clear_bytes((uint8_t *)B_split, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
        clear_bytes((uint8_t *)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
        clear_bytes(randomness, CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A);
        clear_bytes(shake_input_seedSE, 1 + BYTES_SEED_SE);
        return 1;
    }
    PROF_ADD(c_quant);

    PROF_MARK(c_pack);
    frodo_pack(pk_b, PK_PACKED_BYTES, B_split, PARAMS_N*PARAMS_NBAR, PARAMS_PK_LOGP);
    PROF_ADD(c_pack);

    memset(sk, 0, CRYPTO_SECRETKEYBYTES);
    memcpy(sk_s, randomness_s, CRYPTO_BYTES);
    memcpy(sk_pk, pk, CRYPTO_PUBLICKEYBYTES);
    memcpy(sk_seedSE, randomness_seedSE, BYTES_SEED_SE);

    PROF_MARK(c_hash);
    shake(sk_pkh, BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);
    PROF_ADD(c_hash);

    clear_bytes((uint8_t *)B_raw, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)B_split, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(randomness, CRYPTO_BYTES + BYTES_SEED_SE);
    clear_bytes(shake_input_seedSE, 1 + BYTES_SEED_SE);
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_DEFINED(randomness, CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A);
#endif
    PROF_END(c_total);
#ifdef PROFILE_ALL_LEVELS
    if (prof_all_enabled()) {
        unsigned long long c_other = c_total - (c_rand + c_seedexp + c_cbd + c_as + c_quant + c_pack + c_hash);
        fprintf(stderr,
                "[profile-all] level=%d api=keygen total=%llu random=%llu seedexp=%llu cbd_s=%llu mul_as=%llu quant_b=%llu pack_pk=%llu hash_aux=%llu other=%llu\n",
                PARAMS_N, c_total, c_rand, c_seedexp, c_cbd, c_as, c_quant, c_pack, c_hash, c_other);
    }
#endif
    return 0;
}


int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // FrodoKEM's key encapsulation with public dithered quantization
    PROF_DECL();
    unsigned long long c_total = 0, c_coins = 0, c_cbd_r = 0, c_atr = 0, c_unpack_pk = 0, c_btr = 0, c_msg = 0, c_qu = 0, c_qv = 0, c_pack = 0, c_hash_ss = 0;
    PROF_BEGIN();
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[CT_C1_PACKED_BYTES];
    uint16_t B_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t B_norm[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp_raw[PARAMS_N*PARAMS_NBAR] = {0};                     // contains secret data
    uint16_t Bp_split[PARAMS_N*PARAMS_NBAR] = {0};                   // contains secret data
    uint16_t V_raw[PARAMS_NBAR*PARAMS_NBAR] = {0};                   // contains secret data
    uint16_t C_split[PARAMS_NBAR*PARAMS_NBAR] = {0};                 // contains secret data
    uint16_t C_enc[PARAMS_NBAR*PARAMS_NBAR] = {0};                   // contains secret data
    uint16_t E_zero_nbar[PARAMS_NBAR*PARAMS_NBAR] = {0};
    ALIGN_HEADER(32) uint16_t Sp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};  // contains secret data
    uint16_t E_zero[PARAMS_N*PARAMS_NBAR] = {0};
    uint8_t G2in[BYTES_PKHASH + BYTES_MU + BYTES_SALT];              // contains secret data via mu
    uint8_t *pkh = &G2in[0];
    uint8_t *mu = &G2in[BYTES_PKHASH];                               // contains secret data
    uint8_t *salt = &G2in[BYTES_PKHASH + BYTES_MU];
    uint8_t G2out[BYTES_SEED_SE + CRYPTO_BYTES];                     // contains secret data
    uint8_t *seedSE = &G2out[0];                                     // contains secret data
    uint8_t *k = &G2out[BYTES_SEED_SE];                              // contains secret data
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];              // contains secret data via Fin_k
    uint8_t *Fin_ct = &Fin[0];
    uint8_t *Fin_k = &Fin[CRYPTO_CIPHERTEXTBYTES];                   // contains secret data
    uint8_t shake_input_seedSE[1 + BYTES_SEED_SE];                   // contains secret data

    PROF_MARK(c_coins);
    shake(pkh, BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);
    if (randombytes(mu, BYTES_MU + BYTES_SALT) != 0)
        return 1;
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_UNDEFINED(mu, BYTES_MU + BYTES_SALT);
    VALGRIND_MAKE_MEM_UNDEFINED(pk, CRYPTO_PUBLICKEYBYTES);
#endif
    shake(G2out, BYTES_SEED_SE + CRYPTO_BYTES, G2in, BYTES_PKHASH + BYTES_MU + BYTES_SALT);
    PROF_ADD(c_coins);

    shake_input_seedSE[0] = 0x96;
    memcpy(&shake_input_seedSE[1], seedSE, BYTES_SEED_SE);
    shake((uint8_t*)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + BYTES_SEED_SE);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        Sp[i] = LE_TO_UINT16(Sp[i]);
    }
    PROF_MARK(c_cbd_r);
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    PROF_ADD(c_cbd_r);
    PROF_MARK(c_atr);
    frodo_mul_add_sa_plus_e(Bp_raw, Sp, E_zero, pk_seedA);
    PROF_ADD(c_atr);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        Bp_raw[i] &= frodo_q_mask_local();
    }
    PROF_MARK(c_qu);
    if (frodo_quantize_dithered_local(Bp_split, Bp_raw, PARAMS_N*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_U, PARAMS_U_LOGP) != 0) {
        return 1;
    }
    PROF_ADD(c_qu);
    PROF_MARK(c_pack);
    frodo_pack(ct_c1, CT_C1_PACKED_BYTES, Bp_split, PARAMS_N*PARAMS_NBAR, PARAMS_U_LOGP);
    PROF_ADD(c_pack);

    PROF_MARK(c_unpack_pk);
    frodo_unpack(B_split, PARAMS_N*PARAMS_NBAR, pk_b, PK_PACKED_BYTES, PARAMS_PK_LOGP);
    if (frodo_reconstruct_dithered_local(B_norm, B_split, PARAMS_N*PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK, PARAMS_PK_LOGP) != 0) {
        return 1;
    }
    PROF_ADD(c_unpack_pk);
    PROF_MARK(c_btr);
    frodo_mul_add_sb_plus_e(V_raw, B_norm, Sp, E_zero_nbar);
    PROF_ADD(c_btr);

    PROF_MARK(c_msg);
    frodo_key_encode(C_enc, (uint16_t*)mu);
    frodo_add(C_enc, V_raw, C_enc);
    PROF_ADD(c_msg);
    PROF_MARK(c_qv);
    if (frodo_quantize_dithered_local(C_split, C_enc, PARAMS_NBAR*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V, PARAMS_V_LOGP) != 0) {
        return 1;
    }
    PROF_ADD(c_qv);
    PROF_MARK(c_pack);
    frodo_pack(ct_c2, CT_C2_PACKED_BYTES, C_split, PARAMS_NBAR*PARAMS_NBAR, PARAMS_V_LOGP);
    PROF_ADD(c_pack);

    memcpy(&ct[CRYPTO_CIPHERTEXTBYTES - BYTES_SALT], salt, BYTES_SALT);
    memcpy(Fin_ct, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(Fin_k, k, CRYPTO_BYTES);
    PROF_MARK(c_hash_ss);
    shake(ss, CRYPTO_BYTES, Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);
    PROF_ADD(c_hash_ss);

    clear_bytes((uint8_t *)B_norm, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Bp_raw, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Bp_split, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)V_raw, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)C_split, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)C_enc, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(mu, BYTES_MU);
    clear_bytes(G2out, BYTES_SEED_SE + CRYPTO_BYTES);
    clear_bytes(Fin_k, CRYPTO_BYTES);
    clear_bytes(shake_input_seedSE, 1 + BYTES_SEED_SE);
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_DEFINED(mu, BYTES_MU);
    VALGRIND_MAKE_MEM_DEFINED(pk, CRYPTO_PUBLICKEYBYTES);
#endif
    PROF_END(c_total);
#ifdef PROFILE_ALL_LEVELS
    if (prof_all_enabled()) {
        unsigned long long c_other = c_total - (c_coins + c_cbd_r + c_atr + c_unpack_pk + c_btr + c_msg + c_qu + c_qv + c_pack + c_hash_ss);
        fprintf(stderr,
                "[profile-all] level=%d api=encaps total=%llu coins_kdf=%llu cbd_r=%llu mul_atr=%llu unpack_recon_pk=%llu mul_btr=%llu msg_add=%llu quant_u=%llu quant_v=%llu pack_ct=%llu hash_ss=%llu other=%llu\n",
                PARAMS_N, c_total, c_coins, c_cbd_r, c_atr, c_unpack_pk, c_btr, c_msg, c_qu, c_qv, c_pack, c_hash_ss, c_other);
    }
#endif
    return 0;
}


int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // FrodoKEM's key decapsulation with public dithered quantization
    PROF_DECL();
    unsigned long long c_total = 0, c_unct = 0, c_recon_uv = 0, c_stu = 0, c_mudec = 0, c_hashcoins = 0, c_reenc_atr = 0, c_reenc_btr = 0, c_reenc_qu = 0, c_reenc_pk = 0, c_reenc_qv = 0, c_ctcmp = 0, c_hashss = 0;
    PROF_BEGIN();
    uint16_t B_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t B_norm[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp_norm[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t BBp_raw[PARAMS_N*PARAMS_NBAR] = {0};                     // contains secret data
    uint16_t BBp_split[PARAMS_N*PARAMS_NBAR] = {0};                   // contains secret data
    uint16_t W[PARAMS_NBAR*PARAMS_NBAR] = {0};                        // contains secret data
    uint16_t C_split[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t C_norm[PARAMS_NBAR*PARAMS_NBAR] = {0};                   // contains secret data
    uint16_t CC[PARAMS_NBAR*PARAMS_NBAR] = {0};                       // contains secret data
    uint16_t CC_split[PARAMS_NBAR*PARAMS_NBAR] = {0};                 // contains secret data
    uint16_t E_zero[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t E_zero_nbar[PARAMS_NBAR*PARAMS_NBAR] = {0};
    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[CT_C1_PACKED_BYTES];
    const uint8_t *salt = &ct[CRYPTO_CIPHERTEXTBYTES - BYTES_SALT];
    const uint8_t *sk_s = &sk[0];
    const uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    const uint8_t *sk_seedSE = &sk[SK_OFFSET_SEEDSE];
    uint16_t S[PARAMS_N * PARAMS_NBAR];                               // contains secret data
    const uint8_t *sk_pkh = &sk[SK_OFFSET_PKH];
    const uint8_t *pk_seedA = &sk_pk[0];
    const uint8_t *pk_b = &sk_pk[BYTES_SEED_A];
    uint8_t G2in[BYTES_PKHASH + BYTES_MU + BYTES_SALT];               // contains secret data via muprime
    uint8_t *pkh = &G2in[0];
    uint8_t *muprime = &G2in[BYTES_PKHASH];                           // contains secret data
    uint8_t *G2in_salt = &G2in[BYTES_PKHASH + BYTES_MU];
    uint8_t G2out[BYTES_SEED_SE + CRYPTO_BYTES];                      // contains secret data
    uint8_t *seedSEprime = &G2out[0];                                 // contains secret data
    uint8_t *kprime = &G2out[BYTES_SEED_SE];                          // contains secret data
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];               // contains secret data via Fin_k
    uint8_t *Fin_ct = &Fin[0];
    uint8_t *Fin_k = &Fin[CRYPTO_CIPHERTEXTBYTES];                    // contains secret data
    uint8_t shake_input_seedSEprime[1 + BYTES_SEED_SE];               // contains secret data
    ALIGN_HEADER(32) uint16_t Sp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};  // contains secret data

#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_UNDEFINED(sk, CRYPTO_SECRETKEYBYTES);
    VALGRIND_MAKE_MEM_UNDEFINED(ct, CRYPTO_CIPHERTEXTBYTES);
#endif

    uint8_t shake_input_seedSE[1 + BYTES_SEED_SE];
    shake_input_seedSE[0] = 0x5F;
    memcpy(&shake_input_seedSE[1], sk_seedSE, BYTES_SEED_SE);
    PROF_MARK(c_hashcoins);
    shake((uint8_t*)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + BYTES_SEED_SE);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        S[i] = LE_TO_UINT16(S[i]);
    }
    frodo_sample_n(S, PARAMS_N*PARAMS_NBAR);
    PROF_ADD(c_hashcoins);

    PROF_MARK(c_unct);
    frodo_unpack(Bp_split, PARAMS_N*PARAMS_NBAR, ct_c1, CT_C1_PACKED_BYTES, PARAMS_U_LOGP);
    frodo_unpack(C_split, PARAMS_NBAR*PARAMS_NBAR, ct_c2, CT_C2_PACKED_BYTES, PARAMS_V_LOGP);
    PROF_ADD(c_unct);
    PROF_MARK(c_recon_uv);
    if (frodo_reconstruct_dithered_local(Bp_norm, Bp_split, PARAMS_N*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_U, PARAMS_U_LOGP) != 0 ||
        frodo_reconstruct_dithered_local(C_norm, C_split, PARAMS_NBAR*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V, PARAMS_V_LOGP) != 0) {
        return 1;
    }
    PROF_ADD(c_recon_uv);
    PROF_MARK(c_stu);
    frodo_mul_bs(W, Bp_norm, S);
    PROF_ADD(c_stu);
    PROF_MARK(c_mudec);
    frodo_sub(W, C_norm, W);
    frodo_key_decode((uint16_t*)muprime, W);
    PROF_ADD(c_mudec);

    PROF_MARK(c_hashcoins);
    memcpy(pkh, sk_pkh, BYTES_PKHASH);
    memcpy(G2in_salt, salt, BYTES_SALT);
    shake(G2out, BYTES_SEED_SE + CRYPTO_BYTES, G2in, BYTES_PKHASH + BYTES_MU + BYTES_SALT);

    shake_input_seedSEprime[0] = 0x96;
    memcpy(&shake_input_seedSEprime[1], seedSEprime, BYTES_SEED_SE);
    shake((uint8_t*)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSEprime, 1 + BYTES_SEED_SE);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        Sp[i] = LE_TO_UINT16(Sp[i]);
    }
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    PROF_ADD(c_hashcoins);
    PROF_MARK(c_reenc_atr);
    frodo_mul_add_sa_plus_e(BBp_raw, Sp, E_zero, pk_seedA);
    PROF_ADD(c_reenc_atr);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        BBp_raw[i] &= frodo_q_mask_local();
    }
    PROF_MARK(c_reenc_qu);
    if (frodo_quantize_dithered_local(BBp_split, BBp_raw, PARAMS_N*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_U, PARAMS_U_LOGP) != 0) {
        return 1;
    }
    PROF_ADD(c_reenc_qu);

    PROF_MARK(c_reenc_pk);
    frodo_unpack(B_split, PARAMS_N*PARAMS_NBAR, pk_b, PK_PACKED_BYTES, PARAMS_PK_LOGP);
    if (frodo_reconstruct_dithered_local(B_norm, B_split, PARAMS_N*PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK, PARAMS_PK_LOGP) != 0) {
        return 1;
    }
    PROF_ADD(c_reenc_pk);
    PROF_MARK(c_reenc_btr);
    frodo_mul_add_sb_plus_e(CC, B_norm, Sp, E_zero_nbar);
    PROF_ADD(c_reenc_btr);
    PROF_MARK(c_reenc_qv);
    frodo_key_encode(W, (uint16_t*)muprime);
    frodo_add(CC, CC, W);
    if (frodo_quantize_dithered_local(CC_split, CC, PARAMS_NBAR*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V, PARAMS_V_LOGP) != 0) {
        return 1;
    }
    PROF_ADD(c_reenc_qv);

    memcpy(Fin_ct, ct, CRYPTO_CIPHERTEXTBYTES);

    PROF_MARK(c_ctcmp);
    int8_t selector = ct_verify(Bp_split, BBp_split, PARAMS_N*PARAMS_NBAR) | ct_verify(C_split, CC_split, PARAMS_NBAR*PARAMS_NBAR);
    ct_select((uint8_t*)Fin_k, (uint8_t*)kprime, (uint8_t*)sk_s, CRYPTO_BYTES, selector);
    PROF_ADD(c_ctcmp);
    PROF_MARK(c_hashss);
    shake(ss, CRYPTO_BYTES, Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);
    PROF_ADD(c_hashss);

    clear_bytes((uint8_t *)B_norm, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Bp_norm, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)BBp_raw, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)BBp_split, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)W, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)C_norm, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)CC, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)CC_split, PARAMS_NBAR*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(muprime, BYTES_MU);
    clear_bytes(G2out, BYTES_SEED_SE + CRYPTO_BYTES);
    clear_bytes(Fin_k, CRYPTO_BYTES);
    clear_bytes(shake_input_seedSEprime, 1 + BYTES_SEED_SE);
#ifdef DO_VALGRIND_CHECK
    VALGRIND_MAKE_MEM_DEFINED(sk, CRYPTO_SECRETKEYBYTES);
    VALGRIND_MAKE_MEM_DEFINED(ct, CRYPTO_CIPHERTEXTBYTES);
#endif
    PROF_END(c_total);
#ifdef PROFILE_ALL_LEVELS
    if (prof_all_enabled()) {
        unsigned long long c_other = c_total - (c_unct + c_recon_uv + c_stu + c_mudec + c_hashcoins + c_reenc_atr + c_reenc_btr + c_reenc_qu + c_reenc_pk + c_reenc_qv + c_ctcmp + c_hashss);
        fprintf(stderr,
                "[profile-all] level=%d api=decaps total=%llu unpack_ct=%llu recon_uv=%llu mul_stu=%llu msg_decode=%llu hash_coins=%llu reenc_atr=%llu reenc_btr=%llu reenc_qu=%llu reenc_pk=%llu reenc_qv=%llu ct_compare=%llu hash_ss=%llu other=%llu\n",
                PARAMS_N, c_total, c_unct, c_recon_uv, c_stu, c_mudec, c_hashcoins, c_reenc_atr, c_reenc_btr, c_reenc_qu, c_reenc_pk, c_reenc_qv, c_ctcmp, c_hashss, c_other);
    }
#endif
    return 0;
}
