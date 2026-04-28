/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for Venom-256
*********************************************************************************************/

#ifndef _API_Venom256_H_
#define _API_Venom256_H_


#define CRYPTO_SECRETKEYBYTES  21600
#define CRYPTO_PUBLICKEYBYTES  17504
#define CRYPTO_BYTES              32
#define CRYPTO_CIPHERTEXTBYTES 17568

// Algorithm name
#define CRYPTO_ALGNAME "Venom-256"


int crypto_kem_keypair_Venom256(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Venom256(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Venom256(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
