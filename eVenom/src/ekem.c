/********************************************************************************************
* MAMBA-Venom: Plain-LWE Key Encapsulation
*
* Abstract: Ephemeral KEM with public double-dither quantization
*********************************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "../../common/sha3/fips202.h"
#include "../../common/random/random.h"

#ifdef DO_VALGRIND_CHECK
#include <valgrind/memcheck.h>
#endif

#define DITHER_DOMAIN_PK_1 0xA1
#define DITHER_DOMAIN_PK_2 0xA2
#define DITHER_DOMAIN_U_1  0xB1
#define DITHER_DOMAIN_U_2  0xB2
#define DITHER_DOMAIN_V_1  0xC1
#define DITHER_DOMAIN_V_2  0xC2

#define PK_PACKED_BYTES ((PARAMS_PK_LOGP2 * PARAMS_N * PARAMS_NBAR) / 8)
#define CT_C1_PACKED_BYTES ((PARAMS_U_LOGP2 * PARAMS_N * PARAMS_NBAR) / 8)
#define CT_C2_PACKED_BYTES ((PARAMS_V_LOGP2 * PARAMS_NBAR * PARAMS_NBAR) / 8)

static inline uint16_t q_mask_local(void) { return (uint16_t)((1u << PARAMS_LOGQ) - 1u); }
static inline uint16_t p_mask_local(unsigned int logp) { return (uint16_t)((1u << logp) - 1u); }
static inline uint16_t reconstruct_local(uint16_t x, unsigned int logp) {
    return (uint16_t)((x & p_mask_local(logp)) << (PARAMS_LOGQ - logp));
}

static inline uint16_t quantize_local(uint16_t x, uint16_t d, unsigned int logp)
{
    const unsigned int shift = PARAMS_LOGQ - logp;
    uint32_t z = ((uint32_t)x & q_mask_local()) + ((uint32_t)d & ((1u << shift) - 1u));
    z &= q_mask_local();
    z = (z + (1u << (shift - 1))) >> shift;
    return (uint16_t)(z & p_mask_local(logp));
}

static int expand_dither_local(uint16_t *d, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain, unsigned int logp)
{
    const unsigned int shift = PARAMS_LOGQ - logp;
    const uint16_t mask = (uint16_t)((1u << shift) - 1u);
    uint8_t in[1 + BYTES_SEED_A + BYTES_SALT] = {0};
    uint16_t *raw = (uint16_t *)malloc(n * sizeof(uint16_t));

    if (raw == NULL) return 1;
    in[0] = domain;
    memcpy(&in[1], seed, seedlen);
    shake((uint8_t *)raw, n * sizeof(uint16_t), in, 1 + seedlen);
    for (size_t i = 0; i < n; i++) d[i] = LE_TO_UINT16(raw[i]) & mask;
    clear_bytes((uint8_t *)raw, n * sizeof(uint16_t));
    free(raw);
    return 0;
}

static int double_quantize_local(uint16_t *split, const uint16_t *in, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain1, uint8_t domain2, unsigned int logp1, unsigned int logp2)
{
    uint16_t *d1 = (uint16_t *)malloc(n * sizeof(uint16_t));
    uint16_t *d2 = (uint16_t *)malloc(n * sizeof(uint16_t));

    if (d1 == NULL || d2 == NULL) { free(d1); free(d2); return 1; }
    if (expand_dither_local(d1, n, seed, seedlen, domain1, logp1) != 0 ||
        expand_dither_local(d2, n, seed, seedlen, domain2, logp2) != 0) {
        clear_bytes((uint8_t *)d1, n * sizeof(uint16_t));
        clear_bytes((uint8_t *)d2, n * sizeof(uint16_t));
        free(d1); free(d2); return 1;
    }

    for (size_t i = 0; i < n; i++) {
        uint16_t b1 = quantize_local(in[i], d1[i], logp1);
        uint16_t c1 = (uint16_t)((reconstruct_local(b1, logp1) - d1[i]) & q_mask_local());
        split[i] = quantize_local(c1, d2[i], logp2);
    }

    clear_bytes((uint8_t *)d1, n * sizeof(uint16_t));
    clear_bytes((uint8_t *)d2, n * sizeof(uint16_t));
    free(d1); free(d2);
    return 0;
}

static int reconstruct_second_layer_local(uint16_t *normal, const uint16_t *split, size_t n, const uint8_t *seed, size_t seedlen, uint8_t domain2, unsigned int logp2)
{
    uint16_t *d2 = (uint16_t *)malloc(n * sizeof(uint16_t));
    if (d2 == NULL) return 1;
    if (expand_dither_local(d2, n, seed, seedlen, domain2, logp2) != 0) {
        clear_bytes((uint8_t *)d2, n * sizeof(uint16_t)); free(d2); return 1;
    }
    for (size_t i = 0; i < n; i++) normal[i] = (uint16_t)((reconstruct_local(split[i], logp2) - d2[i]) & q_mask_local());
    clear_bytes((uint8_t *)d2, n * sizeof(uint16_t));
    free(d2);
    return 0;
}

static int kem_keypair(unsigned char* pk, unsigned char* sk)
{
    uint8_t *pk_seedA = &pk[0];
    uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *sk_s = &sk[0];
    uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    uint8_t *sk_S = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];
    uint8_t *sk_pkh = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR];
    uint16_t B_raw[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t B_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t S[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t E_zero[PARAMS_N*PARAMS_NBAR] = {0};
    uint8_t randomness[CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A] = {0};
    uint8_t *randomness_s = &randomness[0];
    uint8_t *randomness_seedSE = &randomness[CRYPTO_BYTES];
    uint8_t *randomness_z = &randomness[CRYPTO_BYTES + BYTES_SEED_SE];
    uint8_t shake_input_seedSE[1 + BYTES_SEED_SE];

    if (randombytes(randomness, CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A) != 0) return 1;
    shake(pk_seedA, BYTES_SEED_A, randomness_z, BYTES_SEED_A);

    shake_input_seedSE[0] = 0x5F;
    memcpy(&shake_input_seedSE[1], randomness_seedSE, BYTES_SEED_SE);
    shake((uint8_t*)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + BYTES_SEED_SE);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) S[i] = LE_TO_UINT16(S[i]);
    frodo_sample_n(S, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_as_plus_e(B_raw, S, E_zero, pk_seedA);

    if (double_quantize_local(B_split, B_raw, PARAMS_N*PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK_1, DITHER_DOMAIN_PK_2, PARAMS_PK_LOGP1, PARAMS_PK_LOGP2) != 0) return 1;

    frodo_pack(pk_b, PK_PACKED_BYTES, B_split, PARAMS_N*PARAMS_NBAR, PARAMS_PK_LOGP2);
    memcpy(sk_s, randomness_s, CRYPTO_BYTES);
    memcpy(sk_pk, pk, CRYPTO_PUBLICKEYBYTES);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) S[i] = UINT16_TO_LE(S[i]);
    memcpy(sk_S, S, 2*PARAMS_N*PARAMS_NBAR);
    shake(sk_pkh, BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);

    clear_bytes((uint8_t *)S, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(randomness, CRYPTO_BYTES + BYTES_SEED_SE + BYTES_SEED_A);
    return 0;
}

static int kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[CT_C1_PACKED_BYTES];
    uint16_t B_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t B_norm[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp_raw[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t V_raw[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t C_split[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t C_enc[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t E_zero_nbar[PARAMS_NBAR*PARAMS_NBAR] = {0};
    ALIGN_HEADER(32) uint16_t Sp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};
    uint16_t E_zero[PARAMS_N*PARAMS_NBAR] = {0};
    uint8_t G2in[BYTES_PKHASH + BYTES_MU + BYTES_SALT] = {0};
    uint8_t *pkh = &G2in[0];
    uint8_t *mu = &G2in[BYTES_PKHASH];
    uint8_t *salt = &G2in[BYTES_PKHASH + BYTES_MU];
    uint8_t G2out[BYTES_SEED_SE + CRYPTO_BYTES];
    uint8_t *seedSE = &G2out[0];
    uint8_t *k = &G2out[BYTES_SEED_SE];
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES];

    shake(pkh, BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);
    if (randombytes(mu, BYTES_MU + BYTES_SALT) != 0) return 1;
    shake(G2out, BYTES_SEED_SE + CRYPTO_BYTES, G2in, BYTES_PKHASH + BYTES_MU + BYTES_SALT);

    uint8_t shake_input_seedSE[1 + BYTES_SEED_SE];
    shake_input_seedSE[0] = 0x96;
    memcpy(&shake_input_seedSE[1], seedSE, BYTES_SEED_SE);
    shake((uint8_t*)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + BYTES_SEED_SE);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) Sp[i] = LE_TO_UINT16(Sp[i]);
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(Bp_raw, Sp, E_zero, pk_seedA);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) Bp_raw[i] &= q_mask_local();

    if (double_quantize_local(Bp_split, Bp_raw, PARAMS_N*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_U_1, DITHER_DOMAIN_U_2, PARAMS_U_LOGP1, PARAMS_U_LOGP2) != 0) return 1;
    frodo_pack(ct_c1, CT_C1_PACKED_BYTES, Bp_split, PARAMS_N*PARAMS_NBAR, PARAMS_U_LOGP2);

    frodo_unpack(B_split, PARAMS_N*PARAMS_NBAR, pk_b, PK_PACKED_BYTES, PARAMS_PK_LOGP2);
    if (reconstruct_second_layer_local(B_norm, B_split, PARAMS_N*PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK_2, PARAMS_PK_LOGP2) != 0) return 1;

    frodo_mul_add_sb_plus_e(V_raw, B_norm, Sp, E_zero_nbar);
    frodo_key_encode(C_enc, (uint16_t*)mu);
    frodo_add(C_enc, V_raw, C_enc);
    if (double_quantize_local(C_split, C_enc, PARAMS_NBAR*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V_1, DITHER_DOMAIN_V_2, PARAMS_V_LOGP1, PARAMS_V_LOGP2) != 0) return 1;
    frodo_pack(ct_c2, CT_C2_PACKED_BYTES, C_split, PARAMS_NBAR*PARAMS_NBAR, PARAMS_V_LOGP2);

    memcpy(&ct[CRYPTO_CIPHERTEXTBYTES - BYTES_SALT], salt, BYTES_SALT);
    memcpy(Fin, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(&Fin[CRYPTO_CIPHERTEXTBYTES], k, CRYPTO_BYTES);
    shake(ss, CRYPTO_BYTES, Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);

    clear_bytes((uint8_t*)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(mu, BYTES_MU);
    clear_bytes(G2out, BYTES_SEED_SE + CRYPTO_BYTES);
    return 0;
}

int crypto_kem_keypair_enc(unsigned char* ct, unsigned char* ss, unsigned char* pk, unsigned char* sk)
{
    if (kem_keypair(pk, sk) != 0) return 1;
    if (kem_enc(ct, ss, pk) != 0) return 1;
    return 0;
}

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    uint16_t B_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t B_norm[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t Bp_norm[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t BBp_raw[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t BBp_split[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t W[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t C_split[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t C_norm[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t CC[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t CC_split[PARAMS_NBAR*PARAMS_NBAR] = {0};
    uint16_t E_zero[PARAMS_N*PARAMS_NBAR] = {0};
    uint16_t E_zero_nbar[PARAMS_NBAR*PARAMS_NBAR] = {0};
    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[CT_C1_PACKED_BYTES];
    const uint8_t *salt = &ct[CRYPTO_CIPHERTEXTBYTES - BYTES_SALT];
    const uint8_t *sk_s = &sk[0];
    const uint8_t *sk_pk = &sk[CRYPTO_BYTES];
    const uint16_t *sk_S = (uint16_t *) &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];
    uint16_t S[PARAMS_N * PARAMS_NBAR];
    const uint8_t *sk_pkh = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR];
    const uint8_t *pk_seedA = &sk_pk[0];
    const uint8_t *pk_b = &sk_pk[BYTES_SEED_A];
    uint8_t G2in[BYTES_PKHASH + BYTES_MU + BYTES_SALT] = {0};
    uint8_t *pkh = &G2in[0];
    uint8_t *muprime = &G2in[BYTES_PKHASH];
    uint8_t *G2in_salt = &G2in[BYTES_PKHASH + BYTES_MU];
    uint8_t G2out[BYTES_SEED_SE + CRYPTO_BYTES] = {0};
    uint8_t *seedSEprime = &G2out[0];
    uint8_t *kprime = &G2out[BYTES_SEED_SE];
    uint8_t Fin[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES] = {0};
    ALIGN_HEADER(32) uint16_t Sp[PARAMS_N*PARAMS_NBAR] ALIGN_FOOTER(32) = {0};

    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) S[i] = LE_TO_UINT16(sk_S[i]);

    frodo_unpack(Bp_split, PARAMS_N*PARAMS_NBAR, ct_c1, CT_C1_PACKED_BYTES, PARAMS_U_LOGP2);
    frodo_unpack(C_split, PARAMS_NBAR*PARAMS_NBAR, ct_c2, CT_C2_PACKED_BYTES, PARAMS_V_LOGP2);
    if (reconstruct_second_layer_local(Bp_norm, Bp_split, PARAMS_N*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_U_2, PARAMS_U_LOGP2) != 0 ||
        reconstruct_second_layer_local(C_norm, C_split, PARAMS_NBAR*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V_2, PARAMS_V_LOGP2) != 0) return 1;

    frodo_mul_bs(W, Bp_norm, S);
    frodo_sub(W, C_norm, W);
    frodo_key_decode((uint16_t*)muprime, W);

    memcpy(pkh, sk_pkh, BYTES_PKHASH);
    memcpy(G2in_salt, salt, BYTES_SALT);
    shake(G2out, BYTES_SEED_SE + CRYPTO_BYTES, G2in, BYTES_PKHASH + BYTES_MU + BYTES_SALT);

    uint8_t shake_input_seedSEprime[1 + BYTES_SEED_SE];
    shake_input_seedSEprime[0] = 0x96;
    memcpy(&shake_input_seedSEprime[1], seedSEprime, BYTES_SEED_SE);
    shake((uint8_t*)Sp, PARAMS_N*PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSEprime, 1 + BYTES_SEED_SE);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) Sp[i] = LE_TO_UINT16(Sp[i]);
    frodo_sample_n(Sp, PARAMS_N*PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(BBp_raw, Sp, E_zero, pk_seedA);
    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) BBp_raw[i] &= q_mask_local();
    if (double_quantize_local(BBp_split, BBp_raw, PARAMS_N*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_U_1, DITHER_DOMAIN_U_2, PARAMS_U_LOGP1, PARAMS_U_LOGP2) != 0) return 1;

    frodo_unpack(B_split, PARAMS_N*PARAMS_NBAR, pk_b, PK_PACKED_BYTES, PARAMS_PK_LOGP2);
    if (reconstruct_second_layer_local(B_norm, B_split, PARAMS_N*PARAMS_NBAR, pk_seedA, BYTES_SEED_A, DITHER_DOMAIN_PK_2, PARAMS_PK_LOGP2) != 0) return 1;
    frodo_mul_add_sb_plus_e(CC, B_norm, Sp, E_zero_nbar);
    frodo_key_encode(W, (uint16_t*)muprime);
    frodo_add(CC, CC, W);
    if (double_quantize_local(CC_split, CC, PARAMS_NBAR*PARAMS_NBAR, salt, BYTES_SALT, DITHER_DOMAIN_V_1, DITHER_DOMAIN_V_2, PARAMS_V_LOGP1, PARAMS_V_LOGP2) != 0) return 1;

    memcpy(Fin, ct, CRYPTO_CIPHERTEXTBYTES);
    int8_t selector = ct_verify(Bp_split, BBp_split, PARAMS_N*PARAMS_NBAR) | ct_verify(C_split, CC_split, PARAMS_NBAR*PARAMS_NBAR);
    ct_select((uint8_t*)&Fin[CRYPTO_CIPHERTEXTBYTES], (uint8_t*)kprime, (uint8_t*)sk_s, CRYPTO_BYTES, selector);
    shake(ss, CRYPTO_BYTES, Fin, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES);

    return 0;
}
