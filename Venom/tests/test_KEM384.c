#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "ds_benchmark.h"
#include "../src/api_venom384.h"

#define SYSTEM_NAME    "Venom-384"
#define crypto_kem_keypair crypto_kem_keypair_Venom384
#define crypto_kem_enc crypto_kem_enc_Venom384
#define crypto_kem_dec crypto_kem_dec_Venom384
#define shake shake256

#include "test_kem.c"
