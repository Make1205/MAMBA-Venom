/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: setting parameters to test Venom-256
*********************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_venom256.h"


#define SYSTEM_NAME    "Venom-256"

#define crypto_kem_keypair            crypto_kem_keypair_Venom256
#define crypto_kem_enc                crypto_kem_enc_Venom256
#define crypto_kem_dec                crypto_kem_dec_Venom256
#define shake                         shake256

#include "test_kem.c"
