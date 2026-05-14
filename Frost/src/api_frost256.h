/********************************************************************************************
* MAMBA-Frost: unstructured LWQ-Z key encapsulation mechanism.
*
* Abstract: parameters and API for MAMBA-Frost-256.
*
* Derived in part from an unstructured LWE KEM implementation framework; retained
* license and provenance notices apply.
*********************************************************************************************/

#ifndef _API_Frost256_H_
#define _API_Frost256_H_


#define CRYPTO_SECRETKEYBYTES  19296
#define CRYPTO_PUBLICKEYBYTES  16672
#define CRYPTO_BYTES              32
#define CRYPTO_CIPHERTEXTBYTES 15448

// Algorithm name
#define CRYPTO_ALGNAME "MAMBA-Frost-256"


int crypto_kem_keypair_Frost256(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Frost256(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Frost256(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
