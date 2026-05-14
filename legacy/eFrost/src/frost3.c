/********************************************************************************************
* MAMBA-Frost: Plain-LWE Key Encapsulation
*
* Abstract: functions for eMAMBA-Frost-3
*           Instantiates "frost_macrify.c" with the necessary matrix arithmetic functions
*********************************************************************************************/

#include "api_frost3.h"
#include "frost_macrify.h"


// Parameters for "eMAMBA-Frost-3"
#define PARAMS_N 976
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 16
#define PARAMS_Q (1 << PARAMS_LOGQ)
#define PARAMS_EXTRACTED_BITS 3
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
#error You have modified the cryptographic parameters. MAMBA-Frost assumes PARAMS_NBAR is a multiple of 8.
#endif

// Selecting SHAKE XOF function for the KEM and noise sampling
#define shake     shake256

// CDF table
uint16_t CDF_TABLE[11] = {5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};
uint16_t CDF_TABLE_LEN = 11;

#define crypto_kem_keypair_enc        crypto_kem_keypair_enc_eFrost976
#define crypto_kem_dec                crypto_kem_dec_eFrost976

#include "ekem.c"
#include "noise.c"
#if defined(USE_REFERENCE)
#include "frost_macrify_reference.c"
#else
#include "frost_macrify.c"
#endif
