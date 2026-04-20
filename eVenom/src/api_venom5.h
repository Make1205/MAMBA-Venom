/********************************************************************************************
* MAMBA-Venom: Plain-LWE Key Encapsulation
*
* Abstract: parameters and API for eMAMBA-Venom-5
*********************************************************************************************/

#ifndef _API_eVenom1344_H_
#define _API_eVenom1344_H_


#define CRYPTO_SECRETKEYBYTES  35024     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES   13456     // sizeof(seed_A) + (PARAMS_PK_LOGP2*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              32
#define CRYPTO_CIPHERTEXTBYTES  12160     // (PARAMS_U_LOGP2*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_V_LOGP2*PARAMS_NBAR*PARAMS_NBAR)/8 + BYTES_SALT

// Algorithm name
#define CRYPTO_ALGNAME "eMAMBA-Venom-5"


int crypto_kem_keypair_enc_eVenom1344(unsigned char* ct, unsigned char* ss, unsigned char* pk, unsigned char* sk);
int crypto_kem_dec_eVenom1344(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
