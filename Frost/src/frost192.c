/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: functions for Frost-192
*           Instantiates "frost_macrify.c" with the necessary matrix arithmetic functions
*********************************************************************************************/

#include "api_frost192.h"
#include "frost_macrify.h"


// Parameters for "Frost-192"
#define PARAMS_N 872
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 16
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 3
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 32
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8
#define BYTES_SALT 32
#define BYTES_SEED_SE (2*CRYPTO_BYTES)
#define BYTES_PKHASH CRYPTO_BYTES
#define PARAMS_PK_LOGP 11
#define PARAMS_U_LOGP  11
#define PARAMS_ETA 1
#define PARAMS_V_LOGP  8

#if (PARAMS_NBAR % 8 != 0)
#error You have modified the cryptographic parameters. FrodoKEM assumes PARAMS_NBAR is a multiple of 8.
#endif

// Selecting SHAKE XOF function for the KEM and noise sampling
#define shake     shake256

// CDF table
uint16_t CDF_TABLE[11] = {5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};
uint16_t CDF_TABLE_LEN = 11;

#define crypto_kem_keypair            crypto_kem_keypair_Frost192
#define crypto_kem_enc                crypto_kem_enc_Frost192
#define crypto_kem_dec                crypto_kem_dec_Frost192

#include "kem.c"
#include "noise.c"
#if defined(USE_REFERENCE)
#include "frost_macrify_reference.c"
#else
#include "frost_macrify.c"
#endif
