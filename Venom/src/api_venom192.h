/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for Venom-192
*********************************************************************************************/

#ifndef _API_Venom192_H_
#define _API_Venom192_H_


#define CRYPTO_SECRETKEYBYTES  14736
#define CRYPTO_PUBLICKEYBYTES  11744
#define CRYPTO_BYTES              24
#define CRYPTO_CIPHERTEXTBYTES 11792

// Algorithm name
#define CRYPTO_ALGNAME "Venom-192"


int crypto_kem_keypair_Venom192(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Venom192(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Venom192(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
