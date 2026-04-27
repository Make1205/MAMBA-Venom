/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for Venom-256
*********************************************************************************************/

#ifndef _API_Venom256_H_
#define _API_Venom256_H_


#define CRYPTO_SECRETKEYBYTES  35040     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES  13472     // sizeof(seed_A) + (PARAMS_PK_LOGP*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              32
#define CRYPTO_CIPHERTEXTBYTES 13504     // (PARAMS_U_LOGP*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_V_LOGP*PARAMS_NBAR*PARAMS_NBAR)/8 + BYTES_SALT

// Algorithm name
#define CRYPTO_ALGNAME "Venom-256"


int crypto_kem_keypair_Venom256(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Venom256(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Venom256(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
