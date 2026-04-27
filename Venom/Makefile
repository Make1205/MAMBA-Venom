####  Makefile for compilation on Unix-like operative systems  ####

CC=gcc
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCHITECTURE=_AMD64_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(ARCH)" "PPC"
    ARCHITECTURE=_PPC_
    USE_OPT_LEVEL=_REFERENCE_
else ifeq "$(ARCH)" "s390x"
    ARCHITECTURE=_S390X_
    USE_OPT_LEVEL=_REFERENCE_
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
    USE_OPT_LEVEL=_FAST_
endif

ifeq "$(OPT_LEVEL)" "REFERENCE"
    USE_OPT_LEVEL=_REFERENCE_
else ifeq "$(OPT_LEVEL)" "FAST_GENERIC"
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(OPT_LEVEL)" "FAST"
    ifeq "$(ARCHITECTURE)" "_AMD64_"
        USE_OPT_LEVEL=_FAST_
    endif
endif

USE_GENERATION_A=_AES128_FOR_A_
ifeq "$(GENERATION_A)" "AES128"
    USE_GENERATION_A=_AES128_FOR_A_
else ifeq "$(GENERATION_A)" "SHAKE128"
    USE_GENERATION_A=_SHAKE128_FOR_A_
endif

ifeq "$(ARCH)" "ARM"
    ARM_SETTING=-lrt
endif

USING_OPENSSL=_USE_OPENSSL_
ifeq "$(USE_OPENSSL)" "FALSE"
    USING_OPENSSL=NO_OPENSSL
endif

OPENSSL_INCLUDE_DIR=/usr/include
OPENSSL_LIB_DIR=/usr/lib

AR=ar rcs
RANLIB=ranlib
LN=ln -s

VALGRIND_CFLAGS=
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
VALGRIND_CFLAGS= -g -O0 -DDO_VALGRIND_CHECK
endif

ifeq "$(EXTRA_CFLAGS)" ""
CFLAGS= -O3 
else
CFLAGS= $(EXTRA_CFLAGS)
endif
CFLAGS+= $(VALGRIND_CFLAGS)
CFLAGS+= -std=gnu11 -Wall -Wextra -DNIX -D $(ARCHITECTURE) -D $(USE_OPT_LEVEL) -D $(USE_GENERATION_A) -D $(USING_OPENSSL)
ifeq "$(CC)" "gcc"
ifneq "$(ARCHITECTURE)" "_PPC_"
ifneq "$(ARCHITECTURE)" "_S390X_"
CFLAGS+= -march=native
endif
endif
endif

ifeq "$(USE_OPENSSL)" "FALSE"
LDFLAGS=-lm
else
CFLAGS+= -I$(OPENSSL_INCLUDE_DIR)
LDFLAGS=-lm -L$(OPENSSL_LIB_DIR) -lssl -lcrypto
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
ifeq "$(USE_OPT_LEVEL)" "_FAST_"
CFLAGS += -mavx2 -maes -msse2
endif
endif

.PHONY: all check clean prettyprint

all: lib128 lib192 lib256 tests KATS

objs/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/venom128.o: src/venom128.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/venom192.o: src/venom192.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/venom256.o: src/venom256.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

# RAND
objs/random/random.o: ../common/random/random.c ../common/random/random.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/random/random.c -o objs/random/random.o
RAND_OBJS := objs/random/random.o

# KEM_FRODO
KEM_FRODO640_OBJS := $(addprefix objs/, venom128.o util.o)
KEM_FRODO640_HEADERS := $(addprefix src/, api_venom128.h config.h venom_macrify.h)
$(KEM_FRODO640_OBJS): $(KEM_FRODO640_HEADERS) $(addprefix src/, kem.c noise.c util.c)

KEM_FRODO976_OBJS := $(addprefix objs/, venom192.o util.o)
KEM_FRODO976_HEADERS := $(addprefix src/, api_venom192.h config.h venom_macrify.h)
$(KEM_FRODO976_OBJS): $(KEM_FRODO976_HEADERS) $(addprefix src/, kem.c noise.c util.c)

KEM_FRODO1344_OBJS := $(addprefix objs/, venom256.o util.o)
KEM_FRODO1344_HEADERS := $(addprefix src/, api_venom256.h config.h venom_macrify.h)
$(KEM_FRODO1344_OBJS): $(KEM_FRODO1344_HEADERS) $(addprefix src/, kem.c noise.c util.c)

# AES
ifeq "$(USE_OPENSSL)" "FALSE" 
ifeq "$(USE_OPT_LEVEL)" "_FAST_"
# AES_NI
objs/aes/aes_ni.o: ../common/aes/aes_ni.c ../common/aes/aes.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/aes/aes_ni.c -o objs/aes/aes_ni.o
AES_OBJS := objs/aes/aes_ni.o
else
objs/aes/aes_c.o: ../common/aes/aes_c.c ../common/aes/aes.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/aes/aes_c.c -o objs/aes/aes_c.o
AES_OBJS := objs/aes/aes_c.o
endif
else
objs/aes/aes_openssl.o: ../common/aes/aes_openssl.c ../common/aes/aes_openssl.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/aes/aes_openssl.c -o objs/aes/aes_openssl.o
AES_OBJS := objs/aes/aes_openssl.o
endif

# SHAKE
objs/sha3/fips202.o: ../common/sha3/fips202.c ../common/sha3/fips202.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/sha3/fips202.c -o objs/sha3/fips202.o
SHAKE_OBJS := objs/sha3/fips202.o

ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(GENERATION_A)" "SHAKE128"
# SHAKEx4
objs/sha3/fips202x4.o: ../common/sha3/fips202x4.c ../common/sha3/fips202x4.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/sha3/fips202x4.c -o objs/sha3/fips202x4.o

objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o: ../common/sha3/keccak4x/KeccakP-1600-times4-SIMD256.c ../common/sha3/keccak4x/KeccakP-1600-times4-SnP.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/sha3/keccak4x/KeccakP-1600-times4-SIMD256.c -o objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o

SHAKEx4_OBJS := objs/sha3/fips202x4.o objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o
endif
endif

lib128: $(KEM_FRODO640_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf venom128
	mkdir venom128
	$(AR) venom128/libvenom.a $^
	$(RANLIB) venom128/libvenom.a

lib192: $(KEM_FRODO976_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf venom192
	mkdir venom192
	$(AR) venom192/libvenom.a $^
	$(RANLIB) venom192/libvenom.a

lib256: $(KEM_FRODO1344_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf venom256
	mkdir venom256
	$(AR) venom256/libvenom.a $^
	$(RANLIB) venom256/libvenom.a

tests: lib128 lib192 lib256 tests/ds_benchmark.h
	$(CC) $(CFLAGS) -L./venom128 tests/test_KEM128.c -lvenom $(LDFLAGS) -o venom128/test_KEM $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./venom192 tests/test_KEM192.c -lvenom $(LDFLAGS) -o venom192/test_KEM $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./venom256 tests/test_KEM256.c -lvenom $(LDFLAGS) -o venom256/test_KEM $(ARM_SETTING)

lib128_for_KATs: $(KEM_FRODO640_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) venom128/libvenom_for_testing.a $^
	$(RANLIB) venom128/libvenom_for_testing.a

lib192_for_KATs: $(KEM_FRODO976_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) venom192/libvenom_for_testing.a $^
	$(RANLIB) venom192/libvenom_for_testing.a

lib256_for_KATs: $(KEM_FRODO1344_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) venom256/libvenom_for_testing.a $^
	$(RANLIB) venom256/libvenom_for_testing.a

KATS: lib128_for_KATs lib192_for_KATs lib256_for_KATs
ifeq "$(GENERATION_A)" "SHAKE128"
	$(CC) $(CFLAGS) -L./venom128 tests/PQCtestKAT_kem128_shake.c tests/rng.c -lvenom_for_testing $(LDFLAGS) -o venom128/PQCtestKAT_kem_shake $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./venom192 tests/PQCtestKAT_kem192_shake.c tests/rng.c -lvenom_for_testing $(LDFLAGS) -o venom192/PQCtestKAT_kem_shake $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./venom256 tests/PQCtestKAT_kem256_shake.c tests/rng.c -lvenom_for_testing $(LDFLAGS) -o venom256/PQCtestKAT_kem_shake $(ARM_SETTING)
else
	$(CC) $(CFLAGS) -L./venom128 tests/PQCtestKAT_kem128.c tests/rng.c -lvenom_for_testing $(LDFLAGS) -o venom128/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./venom192 tests/PQCtestKAT_kem192.c tests/rng.c -lvenom_for_testing $(LDFLAGS) -o venom192/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./venom256 tests/PQCtestKAT_kem256.c tests/rng.c -lvenom_for_testing $(LDFLAGS) -o venom256/PQCtestKAT_kem $(ARM_SETTING)
endif

check: tests

test128:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 venom128/test_KEM
else
	venom128/test_KEM
endif

test192:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 venom192/test_KEM
else
	venom192/test_KEM
endif

test256:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 venom256/test_KEM
else
	venom256/test_KEM
endif

clean:
	rm -rf objs *.req venom128 venom192 venom256
	find . -name .DS_Store -type f -delete

prettyprint:
	astyle --style=java --indent=tab --pad-header --pad-oper --align-pointer=name --align-reference=name --suffix=none src/*.h src/*/*.h src/*/*.c
