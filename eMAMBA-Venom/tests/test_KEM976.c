/********************************************************************************************
* MAMBA-Venom: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test eMAMBA-Venom-976
*********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_efrodo976.h"


#define SYSTEM_NAME    "eMAMBA-Venom-976"

#define crypto_kem_keypair_enc        crypto_kem_keypair_enc_eVenom976
#define crypto_kem_dec                crypto_kem_dec_eVenom976
#define shake                         shake256

#include "test_kem.c"
