/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: functions for Venom-256
*           Instantiates "venom_macrify.c" with the necessary matrix arithmetic functions
*********************************************************************************************/

#include "api_venom256.h"
#include "venom_macrify.h"


// Parameters for "Venom-256"
#define PARAMS_N 1344
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 15
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 1
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 32
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8
#define BYTES_SALT 32
#define BYTES_SEED_SE (2*CRYPTO_BYTES)
#define BYTES_PKHASH CRYPTO_BYTES
#define PARAMS_PK_LOGP 10
#define PARAMS_U_LOGP  10
#define PARAMS_V_LOGP  4

#if (PARAMS_NBAR % 8 != 0)
#error You have modified the cryptographic parameters. FrodoKEM assumes PARAMS_NBAR is a multiple of 8.
#endif

// Selecting SHAKE XOF function for the KEM and noise sampling
#define shake     shake256

// CDF table
uint16_t CDF_TABLE[7] = {9142, 23462, 30338, 32361, 32725, 32765, 32767};
uint16_t CDF_TABLE_LEN = 7;

#define crypto_kem_keypair            crypto_kem_keypair_Venom256
#define crypto_kem_enc                crypto_kem_enc_Venom256
#define crypto_kem_dec                crypto_kem_dec_Venom256

#include "kem.c"
#include "noise.c"
#if defined(USE_REFERENCE)
#include "venom_macrify_reference.c"
#else
// By default, keep AVX2 disabled for this parameter set due to historical
// runtime stability issues under aggressive optimization.
// Define FORCE_USE_AVX2_FOR_L256 to benchmark/enable AVX2 on Level-192/256.
#if !defined(FORCE_USE_AVX2_FOR_L256)
#if defined(USE_AVX2)
#undef USE_AVX2
#endif
#endif
#include "venom_macrify.c"
#endif
