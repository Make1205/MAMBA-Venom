#include <stdlib.h>
#include <string.h>
#include "venom_u32_core.h"
#include "venom_macrify.h"
#include "../../common/sha3/fips202.h"

static inline uint32_t qmask_mul_u32(void) { return (1u << PARAMS_LOGQ) - 1u; }

static int expand_a_matrix(uint32_t *A, const uint8_t *seed_A)
{
    uint8_t in[2 + BYTES_SEED_A];
    uint8_t *row = (uint8_t *)malloc((size_t)PARAMS_N * 4);
    if (!row) return 1;
    memcpy(&in[2], seed_A, BYTES_SEED_A);
    for (size_t i = 0; i < PARAMS_N; i++) {
        in[0] = (uint8_t)(i & 0xFF);
        in[1] = (uint8_t)((i >> 8) & 0xFF);
        shake128(row, (unsigned long long)PARAMS_N * 4, in, sizeof(in));
        for (size_t j = 0; j < PARAMS_N; j++) {
            uint32_t v = (uint32_t)row[4*j] | ((uint32_t)row[4*j+1] << 8) | ((uint32_t)row[4*j+2] << 16) | ((uint32_t)row[4*j+3] << 24);
            A[i*PARAMS_N + j] = v & qmask_mul_u32();
        }
    }
    clear_bytes(row, (size_t)PARAMS_N * 4);
    free(row);
    return 0;
}

int venom_mul_add_as_plus_e_u32(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A)
{
    uint32_t *A = (uint32_t *)malloc((size_t)PARAMS_N * PARAMS_N * sizeof(uint32_t));
    if (!A) return 0;
    if (expand_a_matrix(A, seed_A) != 0) { free(A); return 0; }

    for (size_t i = 0; i < PARAMS_N; i++) {
        for (size_t k = 0; k < PARAMS_NBAR; k++) {
            int64_t sum = e[i*PARAMS_NBAR + k];
            for (size_t j = 0; j < PARAMS_N; j++) {
                sum += (int64_t)A[i*PARAMS_N + j] * (int64_t)s[k*PARAMS_N + j];
            }
            out[i*PARAMS_NBAR + k] = (uint32_t)sum & qmask_mul_u32();
        }
    }
    clear_bytes((uint8_t *)A, (size_t)PARAMS_N * PARAMS_N * sizeof(uint32_t));
    free(A);
    return 1;
}

int venom_mul_add_sa_plus_e_u32(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A)
{
    uint32_t *A = (uint32_t *)malloc((size_t)PARAMS_N * PARAMS_N * sizeof(uint32_t));
    if (!A) return 0;
    if (expand_a_matrix(A, seed_A) != 0) { free(A); return 0; }

    for (size_t k = 0; k < PARAMS_NBAR; k++) {
        for (size_t i = 0; i < PARAMS_N; i++) {
            int64_t sum = e[k*PARAMS_N + i];
            for (size_t j = 0; j < PARAMS_N; j++) {
                sum += (int64_t)s[k*PARAMS_N + j] * (int64_t)A[j*PARAMS_N + i];
            }
            out[k*PARAMS_N + i] = (uint32_t)sum & qmask_mul_u32();
        }
    }
    clear_bytes((uint8_t *)A, (size_t)PARAMS_N * PARAMS_N * sizeof(uint32_t));
    free(A);
    return 1;
}

void venom_mul_bs_u32(uint32_t *out, const uint32_t *b, const int32_t *s)
{
    for (size_t i = 0; i < PARAMS_NBAR; i++) {
        for (size_t j = 0; j < PARAMS_NBAR; j++) {
            int64_t sum = 0;
            for (size_t k = 0; k < PARAMS_N; k++) {
                sum += (int64_t)b[i*PARAMS_N + k] * (int64_t)s[j*PARAMS_N + k];
            }
            out[i*PARAMS_NBAR + j] = (uint32_t)sum & qmask_mul_u32();
        }
    }
}

void venom_mul_add_sb_plus_e_u32(uint32_t *out, const uint32_t *b, const int32_t *s, const uint32_t *e)
{
    for (size_t k = 0; k < PARAMS_NBAR; k++) {
        for (size_t i = 0; i < PARAMS_NBAR; i++) {
            int64_t sum = e[k*PARAMS_NBAR + i];
            for (size_t j = 0; j < PARAMS_N; j++) {
                sum += (int64_t)s[k*PARAMS_N + j] * (int64_t)b[j*PARAMS_NBAR + i];
            }
            out[k*PARAMS_NBAR + i] = (uint32_t)sum & qmask_mul_u32();
        }
    }
}

void venom_pack_u32(unsigned char *out, size_t outlen, const uint32_t *in, size_t inlen, unsigned bits)
{
    memset(out, 0, outlen);
    size_t bitpos = 0;
    for (size_t i = 0; i < inlen; i++) {
        uint32_t v = in[i] & ((bits == 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u));
        for (unsigned b = 0; b < bits; b++) {
            if (bitpos >= outlen * 8) return;
            if ((v >> b) & 1u) out[bitpos >> 3] |= (uint8_t)(1u << (bitpos & 7));
            bitpos++;
        }
    }
}

void venom_unpack_u32(uint32_t *out, size_t outlen, const unsigned char *in, size_t inlen, unsigned bits)
{
    memset(out, 0, outlen * sizeof(uint32_t));
    size_t bitpos = 0;
    for (size_t i = 0; i < outlen; i++) {
        uint32_t v = 0;
        for (unsigned b = 0; b < bits; b++) {
            if (bitpos >= inlen * 8) { out[i] = v; return; }
            v |= ((uint32_t)((in[bitpos >> 3] >> (bitpos & 7)) & 1u)) << b;
            bitpos++;
        }
        out[i] = v;
    }
}

void venom_key_encode_u32(uint32_t *out, const uint8_t *in)
{
    const uint32_t step = 1u << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS);
    size_t bitpos = 0;
    for (size_t i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
        uint32_t v = 0;
        for (unsigned b = 0; b < PARAMS_EXTRACTED_BITS; b++) {
            v |= ((uint32_t)((in[bitpos >> 3] >> (bitpos & 7)) & 1u)) << b;
            bitpos++;
        }
        out[i] = (v * step) & qmask_u32();
    }
}

void venom_key_decode_u32(uint8_t *out, const uint32_t *in)
{
    memset(out, 0, BYTES_MU);
    size_t bitpos = 0;
    for (size_t i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
        uint32_t x = in[i] & qmask_u32();
        uint32_t v = (x + (1u << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS - 1))) >> (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS);
        v &= (1u << PARAMS_EXTRACTED_BITS) - 1u;
        for (unsigned b = 0; b < PARAMS_EXTRACTED_BITS; b++) {
            out[bitpos >> 3] |= (uint8_t)(((v >> b) & 1u) << (bitpos & 7));
            bitpos++;
        }
    }
}
