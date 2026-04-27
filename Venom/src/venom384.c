#include "api_venom384.h"
#include "venom_macrify.h"

#define PARAMS_N 2176
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 18
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 6
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 32
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8
#define BYTES_SALT 32
#define BYTES_SEED_SE 32
#define BYTES_PKHASH CRYPTO_BYTES
#define PARAMS_PK_LOGP 16
#define PARAMS_U_LOGP  15
#define PARAMS_V_LOGP  13
#define PARAMS_ETA_S   3
#define PARAMS_ETA_R   3

#define shake shake256

#define crypto_kem_keypair crypto_kem_keypair_Venom384
#define crypto_kem_enc crypto_kem_enc_Venom384
#define crypto_kem_dec crypto_kem_dec_Venom384

#if defined(USE_AVX2)
#undef USE_AVX2
#endif

#include "kem_u32.c"
#include "noise_u32.c"
#include "venom_macrify_u32.c"
