#ifndef KEM_ALGORITHM_INSTANCE_H
#define KEM_ALGORITHM_INSTANCE_H

#define OUTPUT_BLANK_TEST_VECTORS 0
#define ALGORITHM_INSTANCE "Venom-256"

#ifdef __cplusplus
extern "C" {
#endif

#define VENOM_KEM_SUCCESS 0
#define VENOM_KEM_DECAPS_FAIL -1
#define VENOM_KEM_NULL_POINTER -2
#define VENOM_KEM_BAD_PK_LEN -3
#define VENOM_KEM_BAD_SK_LEN -4
#define VENOM_KEM_BAD_CT_LEN -5
#define VENOM_KEM_INTERNAL_ERROR -6

unsigned long long kem_get_pk_len_bytes(void);
unsigned long long kem_get_sk_len_bytes(void);
unsigned long long kem_get_ss_len_bytes(void);
unsigned long long kem_get_ct_len_bytes(void);

int kem_keygen(
    unsigned char *pk, unsigned long long *pk_len_bytes,
    unsigned char *sk, unsigned long long *sk_len_bytes);

int kem_enc(
    unsigned char *pk, unsigned long long pk_len_bytes,
    unsigned char *ss, unsigned long long *ss_len_bytes,
    unsigned char *ct, unsigned long long *ct_len_bytes);

int kem_dec(
    unsigned char *sk, unsigned long long sk_len_bytes,
    unsigned char *ct, unsigned long long ct_len_bytes,
    unsigned char *ss, unsigned long long *ss_len_bytes);

#ifdef __cplusplus
}
#endif

#endif
