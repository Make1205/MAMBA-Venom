/********************************************************************************************
* MAMBA-Frost: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test eMAMBA-Frost-1344
*********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_frost5.h"


#define SYSTEM_NAME    "eMAMBA-Frost-1344"

#define crypto_kem_keypair_enc        crypto_kem_keypair_enc_eFrost1344
#define crypto_kem_dec                crypto_kem_dec_eFrost1344
#define shake                         shake256

#include "test_kem.c"
