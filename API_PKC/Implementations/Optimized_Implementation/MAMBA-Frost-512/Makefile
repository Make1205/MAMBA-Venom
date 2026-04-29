CC ?= gcc
CFLAGS ?= -O2

CFLAGS += -std=c99 -Wall -Wextra -DNIX -D_AMD64_ -D_FAST_ -D_SHAKE128_FOR_A_ -DNO_OPENSSL -D_POSIX_C_SOURCE=200809L
CFLAGS += -mavx2 -maes -msse2
CFLAGS += -DUSE_AVX2_U32
INCLUDES = -I. -I../../../.. -I../../../../Frost/src -I../../../../common/sha3 -I../../../../common/aes -I../../../../common/random

VENOM_SRC = ../../../../Frost/src/venom512.c ../../../../Frost/src/util.c
COMMON_SRC = ../../../../common/sha3/fips202.c ../../../../common/sha3/fips202x4.c ../../../../common/sha3/keccak4x/KeccakP-1600-times4-SIMD256.c ../../../../common/aes/aes_ni.c
API_SRC = KEM_AlgorithmInstance.c drng.c auxfunc.c randombytes_api.c

OBJS = $(VENOM_SRC:.c=.o) $(COMMON_SRC:.c=.o) $(API_SRC:.c=.o)

all: KAT_KEM

KAT_KEM: KAT_KEM.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -lm -o $@

KAT: KAT_KEM

clean:
	rm -f KAT_KEM *.o
	rm -f ../../../../Frost/src/*.o ../../../../common/sha3/*.o ../../../../common/sha3/keccak4x/*.o ../../../../common/aes/*.o
	rm -rf output
