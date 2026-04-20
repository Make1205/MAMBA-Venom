/********************************************************************************************
* MAMBA-Venom: Plain-LWE Key Encapsulation
*
* Abstract: parameters and API for eMAMBA-Venom-3
*********************************************************************************************/

#ifndef _API_eVenom976_H_
#define _API_eVenom976_H_


#define CRYPTO_SECRETKEYBYTES  25440     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES   9776     // sizeof(seed_A) + (PARAMS_PK_LOGP2*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              24
#define CRYPTO_CIPHERTEXTBYTES  8848     // (PARAMS_U_LOGP2*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_V_LOGP2*PARAMS_NBAR*PARAMS_NBAR)/8 + BYTES_SALT

// Algorithm name
#define CRYPTO_ALGNAME "eMAMBA-Venom-3"


int crypto_kem_keypair_enc_eVenom976(unsigned char *ct, unsigned char *ss, unsigned char *pk, unsigned char* sk);
int crypto_kem_dec_eVenom976(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
