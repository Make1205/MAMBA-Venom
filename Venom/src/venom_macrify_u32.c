#include <stdlib.h>
#include <string.h>
#include "venom_u32_core.h"
#include "venom_macrify.h"
#include "../../common/sha3/fips202.h"
#include <stdio.h>

static inline uint32_t qmask_mul_u32(void) { return (1u << PARAMS_LOGQ) - 1u; }
static int u32_profile_enabled_mul(void)
{
    const char *p = getenv("PROFILE_U32");
    return (p != NULL && strcmp(p, "1") == 0);
}
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static inline unsigned long long mul_now_cycles(void) { return __rdtsc(); }
#else
#include <time.h>
static inline unsigned long long mul_now_cycles(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}
#endif

static void expand_a_row(uint32_t *row, uint8_t *row_bytes, uint16_t row_idx, const uint8_t *seed_A)
{
    uint8_t in[2 + BYTES_SEED_A];
    memcpy(&in[2], seed_A, BYTES_SEED_A);
    in[0] = (uint8_t)(row_idx & 0xFF);
    in[1] = (uint8_t)((row_idx >> 8) & 0xFF);
    shake128(row_bytes, (unsigned long long)PARAMS_N * 4, in, sizeof(in));
    for (size_t j = 0; j < PARAMS_N; j++) {
        uint32_t v = (uint32_t)row_bytes[4*j] | ((uint32_t)row_bytes[4*j+1] << 8) | ((uint32_t)row_bytes[4*j+2] << 16) | ((uint32_t)row_bytes[4*j+3] << 24);
        row[j] = v & qmask_mul_u32();
    }
}

int venom_mul_add_as_plus_e_u32(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A)
{
    unsigned long long c0 = mul_now_cycles(), c_expand = 0, c_mac = 0, c1;
    uint32_t *row = (uint32_t *)malloc((size_t)PARAMS_N * sizeof(uint32_t));
    uint8_t *row_bytes = (uint8_t *)malloc((size_t)PARAMS_N * 4);
    if (!row || !row_bytes) { free(row); free(row_bytes); return 0; }

    for (size_t i = 0; i < PARAMS_N; i++) {
        c1 = mul_now_cycles();
        expand_a_row(row, row_bytes, (uint16_t)i, seed_A);
        c_expand += mul_now_cycles() - c1;
        c1 = mul_now_cycles();
        for (size_t k = 0; k < PARAMS_NBAR; k++) {
            int64_t sum = e[i*PARAMS_NBAR + k];
            for (size_t j = 0; j < PARAMS_N; j++) {
                sum += (int64_t)row[j] * (int64_t)s[k*PARAMS_N + j];
            }
            out[i*PARAMS_NBAR + k] = (uint32_t)sum & qmask_mul_u32();
        }
        c_mac += mul_now_cycles() - c1;
    }
    clear_bytes((uint8_t *)row, (size_t)PARAMS_N * sizeof(uint32_t));
    clear_bytes(row_bytes, (size_t)PARAMS_N * 4);
    free(row);
    free(row_bytes);
    if (u32_profile_enabled_mul()) {
        unsigned long long total = mul_now_cycles() - c0;
        double p_expand = (total == 0) ? 0.0 : (100.0 * (double)c_expand / (double)total);
        double p_mac = (total == 0) ? 0.0 : (100.0 * (double)c_mac / (double)total);
        fprintf(stderr, "[profile-u32] level=%d fn=mul_as details expandA=%llu(%.2f%%) mac=%llu(%.2f%%)\n",
                PARAMS_N, c_expand, p_expand, c_mac, p_mac);
    }
    return 1;
}

int venom_mul_add_sa_plus_e_u32(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A)
{
    unsigned long long c0 = mul_now_cycles(), c_expand = 0, c_mac = 0, c_out = 0, c1;
    uint32_t *row = (uint32_t *)malloc((size_t)PARAMS_N * sizeof(uint32_t));
    uint8_t *row_bytes = (uint8_t *)malloc((size_t)PARAMS_N * 4);
    int64_t *acc = (int64_t *)malloc((size_t)PARAMS_NBAR * PARAMS_N * sizeof(int64_t));
    if (!row || !row_bytes || !acc) { free(row); free(row_bytes); free(acc); return 0; }

    for (size_t k = 0; k < PARAMS_NBAR; k++) {
        for (size_t i = 0; i < PARAMS_N; i++) {
            acc[k*PARAMS_N + i] = e[k*PARAMS_N + i];
        }
    }
    for (size_t i = 0; i < PARAMS_N; i++) {
        c1 = mul_now_cycles();
        expand_a_row(row, row_bytes, (uint16_t)i, seed_A);
        c_expand += mul_now_cycles() - c1;
        c1 = mul_now_cycles();
        for (size_t k = 0; k < PARAMS_NBAR; k++) {
            int64_t si = s[k*PARAMS_N + i];
            for (size_t q = 0; q < PARAMS_N; q++) {
                acc[k*PARAMS_N + q] += si * (int64_t)row[q];
            }
        }
        c_mac += mul_now_cycles() - c1;
    }
    c1 = mul_now_cycles();
    for (size_t k = 0; k < PARAMS_NBAR; k++) {
        for (size_t i = 0; i < PARAMS_N; i++) {
            out[k*PARAMS_N + i] = (uint32_t)acc[k*PARAMS_N + i] & qmask_mul_u32();
        }
    }
    c_out += mul_now_cycles() - c1;
    clear_bytes((uint8_t *)row, (size_t)PARAMS_N * sizeof(uint32_t));
    clear_bytes(row_bytes, (size_t)PARAMS_N * 4);
    clear_bytes((uint8_t *)acc, (size_t)PARAMS_NBAR * PARAMS_N * sizeof(int64_t));
    free(row);
    free(row_bytes);
    free(acc);
    if (u32_profile_enabled_mul()) {
        unsigned long long total = mul_now_cycles() - c0;
        double p_expand = (total == 0) ? 0.0 : (100.0 * (double)c_expand / (double)total);
        double p_mac = (total == 0) ? 0.0 : (100.0 * (double)c_mac / (double)total);
        double p_out = (total == 0) ? 0.0 : (100.0 * (double)c_out / (double)total);
        fprintf(stderr, "[profile-u32] level=%d fn=mul_sa details expandA=%llu(%.2f%%) mac=%llu(%.2f%%) finalize=%llu(%.2f%%)\n",
                PARAMS_N, c_expand, p_expand, c_mac, p_mac, c_out, p_out);
    }
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
    uint64_t bitbuf = 0;
    unsigned bitcnt = 0;
    size_t pos = 0;
    uint64_t mask = (bits == 32) ? 0xFFFFFFFFull : ((1ull << bits) - 1ull);
    for (size_t i = 0; i < inlen; i++) {
        bitbuf |= ((uint64_t)in[i] & mask) << bitcnt;
        bitcnt += bits;
        while (bitcnt >= 8) {
            if (pos >= outlen) return;
            out[pos++] = (uint8_t)(bitbuf & 0xFFu);
            bitbuf >>= 8;
            bitcnt -= 8;
        }
    }
    if (bitcnt > 0 && pos < outlen) {
        out[pos] = (uint8_t)(bitbuf & 0xFFu);
    }
}

void venom_unpack_u32(uint32_t *out, size_t outlen, const unsigned char *in, size_t inlen, unsigned bits)
{
    memset(out, 0, outlen * sizeof(uint32_t));
    uint64_t bitbuf = 0;
    unsigned bitcnt = 0;
    size_t pos = 0;
    uint64_t mask = (bits == 32) ? 0xFFFFFFFFull : ((1ull << bits) - 1ull);
    for (size_t i = 0; i < outlen; i++) {
        while (bitcnt < bits) {
            if (pos >= inlen) { out[i] = (uint32_t)(bitbuf & mask); return; }
            bitbuf |= ((uint64_t)in[pos++]) << bitcnt;
            bitcnt += 8;
        }
        out[i] = (uint32_t)(bitbuf & mask);
        bitbuf >>= bits;
        bitcnt -= bits;
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
