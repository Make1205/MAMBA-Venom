#ifndef _API_Venom512_H_
#define _API_Venom512_H_

#define CRYPTO_SECRETKEYBYTES  67680
#define CRYPTO_PUBLICKEYBYTES  55328
#define CRYPTO_BYTES              64
#define CRYPTO_CIPHERTEXTBYTES 55416

#define CRYPTO_ALGNAME "Venom-512"

int crypto_kem_keypair_Venom512(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc_Venom512(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec_Venom512(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif
