#ifndef VENOM_U32_CORE_H
#define VENOM_U32_CORE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t *arow;
    uint8_t *arow_bytes;
    size_t row_count;
} venom_u32_workspace_t;

int venom_mul_add_as_plus_e_u32(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A, venom_u32_workspace_t *ws);
int venom_mul_add_sa_plus_e_u32(uint32_t *out, const int32_t *s, const uint32_t *e, const uint8_t *seed_A, venom_u32_workspace_t *ws);
void venom_mul_bs_u32(uint32_t *out, const uint32_t *b, const int32_t *s);
void venom_mul_add_sb_plus_e_u32(uint32_t *out, const uint32_t *b, const int32_t *s, const uint32_t *e);

void venom_pack_u32(unsigned char *out, size_t outlen, const uint32_t *in, size_t inlen, unsigned bits);
void venom_unpack_u32(uint32_t *out, size_t outlen, const unsigned char *in, size_t inlen, unsigned bits);
void venom_key_encode_u32(uint32_t *out, const uint8_t *in);
void venom_key_decode_u32(uint8_t *out, const uint32_t *in);

void venom_sample_n_u32(int32_t *s, const uint16_t *rnd, size_t n, unsigned eta);

#endif
