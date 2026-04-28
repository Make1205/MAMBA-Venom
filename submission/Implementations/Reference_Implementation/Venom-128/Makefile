CC ?= gcc
CFLAGS ?= -O2

CFLAGS += -std=c99 -Wall -Wextra -DNIX -D_AMD64_ -D_REFERENCE_ -D_SHAKE128_FOR_A_ -DNO_OPENSSL
INCLUDES = -I. -I../../../.. -I../../../../Venom/src -I../../../../common/sha3 -I../../../../common/aes -I../../../../common/random

VENOM_SRC = ../../../../Venom/src/venom128.c ../../../../Venom/src/util.c
COMMON_SRC = ../../../../common/sha3/fips202.c ../../../../common/aes/aes_c.c
API_SRC = KEM_AlgorithmInstance.c drng.c auxfunc.c randombytes_api.c

OBJS = $(VENOM_SRC:.c=.o) $(COMMON_SRC:.c=.o) $(API_SRC:.c=.o)

all: KAT_KEM

KAT_KEM: KAT_KEM.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -lm -o $@

KAT: KAT_KEM

clean:
	rm -f KAT_KEM *.o
	rm -f ../../../../Venom/src/*.o ../../../../common/sha3/*.o ../../../../common/aes/*.o
	rm -rf output
