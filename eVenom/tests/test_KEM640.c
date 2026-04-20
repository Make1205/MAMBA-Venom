/********************************************************************************************
* MAMBA-Venom: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test eMAMBA-Venom-640
*********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_venom1.h"


#define SYSTEM_NAME    "eMAMBA-Venom-640"

#define crypto_kem_keypair_enc        crypto_kem_keypair_enc_eVenom640
#define crypto_kem_dec                crypto_kem_dec_eVenom640
#define shake                         shake128

#include "test_kem.c"
