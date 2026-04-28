/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for Venom-128
*********************************************************************************************/

#ifndef _API_Venom128_H_
#define _API_Venom128_H_


#define CRYPTO_SECRETKEYBYTES   9056
#define CRYPTO_PUBLICKEYBYTES   7072
#define CRYPTO_BYTES              16
#define CRYPTO_CIPHERTEXTBYTES  6480

// Algorithm name
#define CRYPTO_ALGNAME "Venom-128"


int crypto_kem_keypair_Venom128(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Venom128(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Venom128(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
