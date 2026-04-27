#ifndef _API_Venom384_H_
#define _API_Venom384_H_

#define CRYPTO_SECRETKEYBYTES  41440
#define CRYPTO_PUBLICKEYBYTES  34848
#define CRYPTO_BYTES              48
#define CRYPTO_CIPHERTEXTBYTES 32776

#define CRYPTO_ALGNAME "Venom-384"

int crypto_kem_keypair_Venom384(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Venom384(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Venom384(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif
