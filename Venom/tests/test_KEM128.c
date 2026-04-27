/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test Venom-128
*********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_venom128.h"


#define SYSTEM_NAME    "Venom-128"

#define crypto_kem_keypair            crypto_kem_keypair_Venom128
#define crypto_kem_enc                crypto_kem_enc_Venom128
#define crypto_kem_dec                crypto_kem_dec_Venom128
#define shake                         shake128

#include "test_kem.c"
