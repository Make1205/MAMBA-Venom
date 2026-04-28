#include <stdlib.h>
#include <string.h>
#include "venom_u32_core.h"
#include "venom_macrify.h"
#include "../../common/sha3/fips202.h"
#if defined(__AVX2__)
#include "../../common/sha3/fips202x4.h"
#endif
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

#ifndef VENOM_U32_CACHE_A
#define VENOM_U32_CACHE_A 0
#endif
#ifndef VENOM_U32_A_WORD_BYTES
#define VENOM_U32_A_WORD_BYTES 3
#endif
#if (VENOM_U32_A_WORD_BYTES != 3) && (VENOM_U32_A_WORD_BYTES != 4)
#error "VENOM_U32_A_WORD_BYTES must be 3 or 4"
#endif
#ifndef VENOM_U32_A_PARSE_STYLE
#define VENOM_U32_A_PARSE_STYLE 1
#endif
#define A_ROW_BYTES ((size_t)PARAMS_N * VENOM_U32_A_WORD_BYTES)
static venom_u32_fast_stats_t g_u32_fast_stats = {0};

void venom_u32_fast_stats_reset(void)
{
    memset(&g_u32_fast_stats, 0, sizeof(g_u32_fast_stats));
}

venom_u32_fast_stats_t venom_u32_fast_stats_get(void)
{
    return g_u32_fast_stats;
}

static void expand_a_row_from_bytes(uint32_t *row, const uint8_t *row_bytes)
{
#if VENOM_U32_A_WORD_BYTES == 3
#if VENOM_U32_A_PARSE_STYLE == 1
    size_t j = 0;
    size_t p = 0;
    for (; j + 3 < (size_t)PARAMS_N; j += 4, p += 12) {
        uint32_t v0 = (uint32_t)row_bytes[p] | ((uint32_t)row_bytes[p + 1] << 8) | ((uint32_t)row_bytes[p + 2] << 16);
        uint32_t v1 = (uint32_t)row_bytes[p + 3] | ((uint32_t)row_bytes[p + 4] << 8) | ((uint32_t)row_bytes[p + 5] << 16);
        uint32_t v2 = (uint32_t)row_bytes[p + 6] | ((uint32_t)row_bytes[p + 7] << 8) | ((uint32_t)row_bytes[p + 8] << 16);
        uint32_t v3 = (uint32_t)row_bytes[p + 9] | ((uint32_t)row_bytes[p + 10] << 8) | ((uint32_t)row_bytes[p + 11] << 16);
        row[j] = v0 & qmask_mul_u32();
        row[j + 1] = v1 & qmask_mul_u32();
        row[j + 2] = v2 & qmask_mul_u32();
        row[j + 3] = v3 & qmask_mul_u32();
    }
    for (; j < (size_t)PARAMS_N; j++, p += 3) {
        uint32_t v = (uint32_t)row_bytes[p] | ((uint32_t)row_bytes[p + 1] << 8) | ((uint32_t)row_bytes[p + 2] << 16);
        row[j] = v & qmask_mul_u32();
    }
#else
    for (size_t j = 0; j < PARAMS_N; j++) {
        const size_t p = 3 * j;
        uint32_t v = (uint32_t)row_bytes[p] | ((uint32_t)row_bytes[p + 1] << 8) | ((uint32_t)row_bytes[p + 2] << 16);
        row[j] = v & qmask_mul_u32();
    }
#endif
#else
    for (size_t j = 0; j < PARAMS_N; j++) {
        uint32_t v = (uint32_t)row_bytes[4*j] | ((uint32_t)row_bytes[4*j+1] << 8) | ((uint32_t)row_bytes[4*j+2] << 16) | ((uint32_t)row_bytes[4*j+3] << 24);
        row[j] = v & qmask_mul_u32();
    }
#endif
}

static inline void expandA_row_u32_fast(uint32_t *row, uint8_t *row_bytes, uint16_t row_idx, const uint8_t *seed_A)
{
    uint8_t in[2 + BYTES_SEED_A];
    memcpy(&in[2], seed_A, BYTES_SEED_A);
    in[0] = (uint8_t)(row_idx & 0xFF);
    in[1] = (uint8_t)((row_idx >> 8) & 0xFF);
    shake128(row_bytes, (unsigned long long)A_ROW_BYTES, in, sizeof(in));
    expand_a_row_from_bytes(row, row_bytes);
    g_u32_fast_stats.expand_row_calls += 1;
    g_u32_fast_stats.shake_init_calls += 1;
    g_u32_fast_stats.shake_squeeze_calls += 1;
    g_u32_fast_stats.bytes_squeezed_for_a += A_ROW_BYTES;
}

static inline void expandA_4rows_u32_fast(uint32_t *rows, uint8_t *row_bytes, uint16_t row_idx, size_t count, const uint8_t *seed_A)
{
#if defined(__AVX2__)
    if (count == 4) {
        uint8_t in0[2 + BYTES_SEED_A], in1[2 + BYTES_SEED_A], in2[2 + BYTES_SEED_A], in3[2 + BYTES_SEED_A];
        memcpy(&in0[2], seed_A, BYTES_SEED_A);
        memcpy(&in1[2], seed_A, BYTES_SEED_A);
        memcpy(&in2[2], seed_A, BYTES_SEED_A);
        memcpy(&in3[2], seed_A, BYTES_SEED_A);
        in0[0] = (uint8_t)(row_idx & 0xFF);         in0[1] = (uint8_t)((row_idx >> 8) & 0xFF);
        in1[0] = (uint8_t)((row_idx + 1) & 0xFF);   in1[1] = (uint8_t)(((row_idx + 1) >> 8) & 0xFF);
        in2[0] = (uint8_t)((row_idx + 2) & 0xFF);   in2[1] = (uint8_t)(((row_idx + 2) >> 8) & 0xFF);
        in3[0] = (uint8_t)((row_idx + 3) & 0xFF);   in3[1] = (uint8_t)(((row_idx + 3) >> 8) & 0xFF);
        shake128_4x(row_bytes,
                    row_bytes + A_ROW_BYTES,
                    row_bytes + 2 * A_ROW_BYTES,
                    row_bytes + 3 * A_ROW_BYTES,
                    (unsigned long long)A_ROW_BYTES,
                    in0, in1, in2, in3, sizeof(in0));
        for (size_t r = 0; r < 4; r++) {
            expand_a_row_from_bytes(rows + r * (size_t)PARAMS_N, row_bytes + r * A_ROW_BYTES);
        }
        g_u32_fast_stats.expand_row_calls += 4;
        g_u32_fast_stats.shake_init_calls += 1;
        g_u32_fast_stats.shake_squeeze_calls += 1;
        g_u32_fast_stats.bytes_squeezed_for_a += 4 * A_ROW_BYTES;
        return;
    }
#endif
    for (size_t r = 0; r < count; r++) {
        expandA_row_u32_fast(rows + r * (size_t)PARAMS_N, row_bytes + r * A_ROW_BYTES, (uint16_t)(row_idx + r), seed_A);
    }
}

static int mul_A_times_S_u32_fast(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A, venom_u32_workspace_t *ws)
{
    unsigned long long c0 = mul_now_cycles(), c_expand = 0, c_mac = 0, c1;
    size_t batch_rows = 1;
#if defined(__AVX2__)
    batch_rows = (ws && ws->row_count > 0) ? ws->row_count : 4;
#endif
    if (batch_rows > 4) batch_rows = 4;
    uint32_t *rows = (ws && ws->arow) ? ws->arow : (uint32_t *)malloc((size_t)PARAMS_N * 4 * sizeof(uint32_t));
    uint8_t *row_bytes = (ws && ws->arow_bytes) ? ws->arow_bytes : (uint8_t *)malloc(4 * A_ROW_BYTES);
    int own = !(ws && ws->arow && ws->arow_bytes);
    if (!rows || !row_bytes) { if (own) { free(rows); free(row_bytes); } return 0; }

#if VENOM_U32_CACHE_A
    uint32_t *A = (uint32_t *)malloc((size_t)PARAMS_N * PARAMS_N * sizeof(uint32_t));
    if (!A) { if (own) { free(rows); free(row_bytes); } return 0; }
    for (size_t i = 0; i < (size_t)PARAMS_N; i += batch_rows) {
        size_t cnt = ((size_t)PARAMS_N - i >= batch_rows) ? batch_rows : ((size_t)PARAMS_N - i);
        c1 = mul_now_cycles();
        expandA_4rows_u32_fast(rows, row_bytes, (uint16_t)i, cnt, seed_A);
        c_expand += mul_now_cycles() - c1;
        for (size_t r = 0; r < cnt; r++) {
            memcpy(A + (i + r) * (size_t)PARAMS_N, rows + r * (size_t)PARAMS_N, (size_t)PARAMS_N * sizeof(uint32_t));
        }
    }
#endif

    for (size_t i = 0; i < (size_t)PARAMS_N; i++) {
        const uint32_t *row = NULL;
#if VENOM_U32_CACHE_A
        row = A + i * (size_t)PARAMS_N;
#else
        if ((i % batch_rows) == 0) {
            size_t cnt = ((size_t)PARAMS_N - i >= batch_rows) ? batch_rows : ((size_t)PARAMS_N - i);
            c1 = mul_now_cycles();
            expandA_4rows_u32_fast(rows, row_bytes, (uint16_t)i, cnt, seed_A);
            c_expand += mul_now_cycles() - c1;
        }
        row = rows + (i % batch_rows) * (size_t)PARAMS_N;
#endif
        c1 = mul_now_cycles();
        const int32_t *s0 = s + 0*(size_t)PARAMS_N;
        const int32_t *s1 = s + 1*(size_t)PARAMS_N;
        const int32_t *s2 = s + 2*(size_t)PARAMS_N;
        const int32_t *s3 = s + 3*(size_t)PARAMS_N;
        const int32_t *s4 = s + 4*(size_t)PARAMS_N;
        const int32_t *s5 = s + 5*(size_t)PARAMS_N;
        const int32_t *s6 = s + 6*(size_t)PARAMS_N;
        const int32_t *s7 = s + 7*(size_t)PARAMS_N;
        int64_t acc0 = e[i*(size_t)PARAMS_NBAR + 0];
        int64_t acc1 = e[i*(size_t)PARAMS_NBAR + 1];
        int64_t acc2 = e[i*(size_t)PARAMS_NBAR + 2];
        int64_t acc3 = e[i*(size_t)PARAMS_NBAR + 3];
        int64_t acc4 = e[i*(size_t)PARAMS_NBAR + 4];
        int64_t acc5 = e[i*(size_t)PARAMS_NBAR + 5];
        int64_t acc6 = e[i*(size_t)PARAMS_NBAR + 6];
        int64_t acc7 = e[i*(size_t)PARAMS_NBAR + 7];
        for (size_t j = 0; j < (size_t)PARAMS_N; j++) {
            int64_t a = (int64_t)row[j];
            acc0 += a * (int64_t)s0[j];
            acc1 += a * (int64_t)s1[j];
            acc2 += a * (int64_t)s2[j];
            acc3 += a * (int64_t)s3[j];
            acc4 += a * (int64_t)s4[j];
            acc5 += a * (int64_t)s5[j];
            acc6 += a * (int64_t)s6[j];
            acc7 += a * (int64_t)s7[j];
        }
        out[i*(size_t)PARAMS_NBAR + 0] = (uint32_t)acc0 & qmask_mul_u32();
        out[i*(size_t)PARAMS_NBAR + 1] = (uint32_t)acc1 & qmask_mul_u32();
        out[i*(size_t)PARAMS_NBAR + 2] = (uint32_t)acc2 & qmask_mul_u32();
        out[i*(size_t)PARAMS_NBAR + 3] = (uint32_t)acc3 & qmask_mul_u32();
        out[i*(size_t)PARAMS_NBAR + 4] = (uint32_t)acc4 & qmask_mul_u32();
        out[i*(size_t)PARAMS_NBAR + 5] = (uint32_t)acc5 & qmask_mul_u32();
        out[i*(size_t)PARAMS_NBAR + 6] = (uint32_t)acc6 & qmask_mul_u32();
        out[i*(size_t)PARAMS_NBAR + 7] = (uint32_t)acc7 & qmask_mul_u32();
        c_mac += mul_now_cycles() - c1;
    }
    g_u32_fast_stats.mac_ops += (uint64_t)PARAMS_N * (uint64_t)PARAMS_N * (uint64_t)PARAMS_NBAR;
    g_u32_fast_stats.matrix_products += 1;
    if (own) { free(rows); free(row_bytes); }
#if VENOM_U32_CACHE_A
    clear_bytes((uint8_t *)A, (size_t)PARAMS_N * PARAMS_N * sizeof(uint32_t));
    free(A);
#endif
    if (u32_profile_enabled_mul()) {
        unsigned long long total = mul_now_cycles() - c0;
        double p_expand = (total == 0) ? 0.0 : (100.0 * (double)c_expand / (double)total);
        double p_mac = (total == 0) ? 0.0 : (100.0 * (double)c_mac / (double)total);
        fprintf(stderr, "[profile-u32] level=%d fn=mul_as details expandA=%llu(%.2f%%) mac=%llu(%.2f%%)\n",
                PARAMS_N, c_expand, p_expand, c_mac, p_mac);
    }
    return 1;
}

static int mul_AT_times_R_u32_fast(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A, venom_u32_workspace_t *ws)
{
    unsigned long long c0 = mul_now_cycles(), c_expand = 0, c_mac = 0, c_out = 0, c1;
    size_t batch_rows = 1;
#if defined(__AVX2__)
    batch_rows = (ws && ws->row_count > 0) ? ws->row_count : 4;
#endif
    if (batch_rows > 4) batch_rows = 4;
    uint32_t *rows = (ws && ws->arow) ? ws->arow : (uint32_t *)malloc((size_t)PARAMS_N * 4 * sizeof(uint32_t));
    uint8_t *row_bytes = (ws && ws->arow_bytes) ? ws->arow_bytes : (uint8_t *)malloc(4 * A_ROW_BYTES);
    int64_t *acc = (int64_t *)malloc((size_t)PARAMS_NBAR * PARAMS_N * sizeof(int64_t));
    int own = !(ws && ws->arow && ws->arow_bytes);
    if (!rows || !row_bytes || !acc) { if (own) { free(rows); free(row_bytes); } free(acc); return 0; }

    for (size_t k = 0; k < PARAMS_NBAR; k++) {
        for (size_t i = 0; i < PARAMS_N; i++) {
            acc[k*PARAMS_N + i] = e[k*PARAMS_N + i];
        }
    }
    for (size_t i = 0; i < (size_t)PARAMS_N; i++) {
        if ((i % batch_rows) == 0) {
            size_t cnt = ((size_t)PARAMS_N - i >= batch_rows) ? batch_rows : ((size_t)PARAMS_N - i);
            c1 = mul_now_cycles();
            expandA_4rows_u32_fast(rows, row_bytes, (uint16_t)i, cnt, seed_A);
            c_expand += mul_now_cycles() - c1;
        }
        const uint32_t *row = rows + (i % batch_rows) * (size_t)PARAMS_N;
        c1 = mul_now_cycles();
        int64_t si0 = s[0*(size_t)PARAMS_N + i];
        int64_t si1 = s[1*(size_t)PARAMS_N + i];
        int64_t si2 = s[2*(size_t)PARAMS_N + i];
        int64_t si3 = s[3*(size_t)PARAMS_N + i];
        int64_t si4 = s[4*(size_t)PARAMS_N + i];
        int64_t si5 = s[5*(size_t)PARAMS_N + i];
        int64_t si6 = s[6*(size_t)PARAMS_N + i];
        int64_t si7 = s[7*(size_t)PARAMS_N + i];
        int64_t *a0 = acc + 0*(size_t)PARAMS_N;
        int64_t *a1 = acc + 1*(size_t)PARAMS_N;
        int64_t *a2 = acc + 2*(size_t)PARAMS_N;
        int64_t *a3 = acc + 3*(size_t)PARAMS_N;
        int64_t *a4 = acc + 4*(size_t)PARAMS_N;
        int64_t *a5 = acc + 5*(size_t)PARAMS_N;
        int64_t *a6 = acc + 6*(size_t)PARAMS_N;
        int64_t *a7 = acc + 7*(size_t)PARAMS_N;
        for (size_t q = 0; q < (size_t)PARAMS_N; q++) {
            int64_t a = (int64_t)row[q];
            a0[q] += si0 * a;
            a1[q] += si1 * a;
            a2[q] += si2 * a;
            a3[q] += si3 * a;
            a4[q] += si4 * a;
            a5[q] += si5 * a;
            a6[q] += si6 * a;
            a7[q] += si7 * a;
        }
        c_mac += mul_now_cycles() - c1;
    }
    g_u32_fast_stats.mac_ops += (uint64_t)PARAMS_N * (uint64_t)PARAMS_N * (uint64_t)PARAMS_NBAR;
    g_u32_fast_stats.matrix_products += 1;
    c1 = mul_now_cycles();
    for (size_t k = 0; k < PARAMS_NBAR; k++) {
        for (size_t i = 0; i < PARAMS_N; i++) {
            out[k*PARAMS_N + i] = (uint32_t)acc[k*PARAMS_N + i] & qmask_mul_u32();
        }
    }
    c_out += mul_now_cycles() - c1;
    clear_bytes((uint8_t *)acc, (size_t)PARAMS_NBAR * PARAMS_N * sizeof(int64_t));
    if (own) { free(rows); free(row_bytes); }
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

int venom_mul_add_as_plus_e_u32(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A, venom_u32_workspace_t *ws)
{
    return mul_A_times_S_u32_fast(out, s, e, seed_A, ws);
}

int venom_mul_add_sa_plus_e_u32(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A, venom_u32_workspace_t *ws)
{
    return mul_AT_times_R_u32_fast(out, s, e, seed_A, ws);
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
