#include "KEM_AlgorithmInstance.h"
#include "drng.h"
#include <stddef.h>

#define CRYPTO_SECRETKEYBYTES   9056ULL
#define CRYPTO_PUBLICKEYBYTES   7072ULL
#define CRYPTO_BYTES              16ULL
#define CRYPTO_CIPHERTEXTBYTES  6480ULL

int crypto_kem_keypair_Venom128(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Venom128(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Venom128(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

extern DRNG_ctx drng_algorithm;

unsigned long long kem_get_pk_len_bytes(void) { return CRYPTO_PUBLICKEYBYTES; }
unsigned long long kem_get_sk_len_bytes(void) { return CRYPTO_SECRETKEYBYTES; }
unsigned long long kem_get_ss_len_bytes(void) { return CRYPTO_BYTES; }
unsigned long long kem_get_ct_len_bytes(void) { return CRYPTO_CIPHERTEXTBYTES; }

/* Generate MAMBA-Frost-128 keypair and output lengths. */
int kem_keygen(
    unsigned char *pk, unsigned long long *pk_len_bytes,
    unsigned char *sk, unsigned long long *sk_len_bytes)
{
    if (pk == NULL || sk == NULL || pk_len_bytes == NULL || sk_len_bytes == NULL) {
        return VENOM_KEM_NULL_POINTER;
    }

    *pk_len_bytes = kem_get_pk_len_bytes();
    *sk_len_bytes = kem_get_sk_len_bytes();

    if (crypto_kem_keypair_Venom128(pk, sk) != 0) {
        return VENOM_KEM_INTERNAL_ERROR;
    }

    return VENOM_KEM_SUCCESS;
}

/* Encapsulate with MAMBA-Frost-128 public key and output lengths. */
int kem_enc(
    unsigned char *pk, unsigned long long pk_len_bytes,
    unsigned char *ss, unsigned long long *ss_len_bytes,
    unsigned char *ct, unsigned long long *ct_len_bytes)
{
    if (pk == NULL || ss == NULL || ct == NULL || ss_len_bytes == NULL || ct_len_bytes == NULL) {
        return VENOM_KEM_NULL_POINTER;
    }
    if (pk_len_bytes != kem_get_pk_len_bytes()) {
        return VENOM_KEM_BAD_PK_LEN;
    }

    *ss_len_bytes = kem_get_ss_len_bytes();
    *ct_len_bytes = kem_get_ct_len_bytes();

    if (crypto_kem_enc_Venom128(ct, ss, pk) != 0) {
        return VENOM_KEM_INTERNAL_ERROR;
    }

    return VENOM_KEM_SUCCESS;
}

/* Decapsulate MAMBA-Frost-128 ciphertext and output shared-secret length. */
int kem_dec(
    unsigned char *sk, unsigned long long sk_len_bytes,
    unsigned char *ct, unsigned long long ct_len_bytes,
    unsigned char *ss, unsigned long long *ss_len_bytes)
{
    int ret;
    if (sk == NULL || ct == NULL || ss == NULL || ss_len_bytes == NULL) {
        return VENOM_KEM_NULL_POINTER;
    }
    if (sk_len_bytes != kem_get_sk_len_bytes()) {
        return VENOM_KEM_BAD_SK_LEN;
    }
    if (ct_len_bytes != kem_get_ct_len_bytes()) {
        return VENOM_KEM_BAD_CT_LEN;
    }

    *ss_len_bytes = kem_get_ss_len_bytes();
    ret = crypto_kem_dec_Venom128(ss, ct, sk);
    if (ret == 0) {
        return VENOM_KEM_SUCCESS;
    }
    return VENOM_KEM_DECAPS_FAIL;
}
