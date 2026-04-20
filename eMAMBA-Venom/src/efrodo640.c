/********************************************************************************************
* MAMBA-Venom: Plain-LWE Key Encapsulation
*
* Abstract: functions for eMAMBA-Venom-1
*           Instantiates "frodo_macrify.c" with the necessary matrix arithmetic functions
*********************************************************************************************/

#include "api_efrodo640.h"
#include "frodo_macrify.h"


// Parameters for "eMAMBA-Venom-1"
#define PARAMS_N 640
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 15
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 2
#define PARAMS_STRIPE_STEP 8
#define PARAMS_PARALLEL 4
#define BYTES_SEED_A 16
#define BYTES_MU (PARAMS_EXTRACTED_BITS*PARAMS_NBAR*PARAMS_NBAR)/8
#define BYTES_SALT 32
#define BYTES_SEED_SE (2*CRYPTO_BYTES)
#define BYTES_PKHASH CRYPTO_BYTES
#define PARAMS_PK_LOGP1 12
#define PARAMS_PK_LOGP2 10
#define PARAMS_U_LOGP1  12
#define PARAMS_U_LOGP2  9
#define PARAMS_V_LOGP1  12
#define PARAMS_V_LOGP2  4

#if (PARAMS_NBAR % 8 != 0)
#error You have modified the cryptographic parameters. MAMBA-Venom assumes PARAMS_NBAR is a multiple of 8.
#endif

// Selecting SHAKE XOF function for the KEM and noise sampling
#define shake     shake128

// CDF table
uint16_t CDF_TABLE[13] = {4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767};
uint16_t CDF_TABLE_LEN = 13;

#define crypto_kem_keypair_enc        crypto_kem_keypair_enc_eVenom640
#define crypto_kem_dec                crypto_kem_dec_eVenom640

#include "ekem.c"
#include "noise.c"
#if defined(USE_REFERENCE)
#include "frodo_macrify_reference.c"
#else
#include "frodo_macrify.c"
#endif
