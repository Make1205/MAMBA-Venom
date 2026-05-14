/********************************************************************************************
* MAMBA-Frost: unstructured LWQ-Z key encapsulation mechanism.
*
* Abstract: parameters and API for MAMBA-Frost-128.
*
* Derived in part from an unstructured LWE KEM implementation framework; retained
* license and provenance notices apply.
*********************************************************************************************/

#ifndef _API_Frost128_H_
#define _API_Frost128_H_


#define CRYPTO_SECRETKEYBYTES  6752
#define CRYPTO_PUBLICKEYBYTES  5152
#define CRYPTO_BYTES              16
#define CRYPTO_CIPHERTEXTBYTES 5216

// Algorithm name
#define CRYPTO_ALGNAME "MAMBA-Frost-128"


int crypto_kem_keypair_Frost128(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Frost128(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Frost128(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
