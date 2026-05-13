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
ifeq "$(USE_OPT_LEVEL)" "_FAST_"
CFLAGS+= -DUSE_AVX2_U32
endif
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

.PHONY: all check clean prettyprint size_test

all: lib128 lib192 lib256 lib384 lib512 tests KATS size_test

objs/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/frost128.o: src/frost128.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/frost192.o: src/frost192.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/frost256.o: src/frost256.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/frost384.o: src/frost384.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/frost512.o: src/frost512.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

# RAND
objs/random/random.o: ../common/random/random.c ../common/random/random.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/random/random.c -o objs/random/random.o
RAND_OBJS := objs/random/random.o

# KEM_FRODO
KEM_FRODO640_OBJS := $(addprefix objs/, frost128.o util.o)
KEM_FRODO640_HEADERS := $(addprefix src/, api_frost128.h config.h frost_macrify.h)
$(KEM_FRODO640_OBJS): $(KEM_FRODO640_HEADERS) $(addprefix src/, kem.c noise.c util.c)

KEM_FRODO976_OBJS := $(addprefix objs/, frost192.o util.o)
KEM_FRODO976_HEADERS := $(addprefix src/, api_frost192.h config.h frost_macrify.h)
$(KEM_FRODO976_OBJS): $(KEM_FRODO976_HEADERS) $(addprefix src/, kem.c noise.c util.c)

KEM_FRODO1344_OBJS := $(addprefix objs/, frost256.o util.o)
KEM_FRODO1344_HEADERS := $(addprefix src/, api_frost256.h config.h frost_macrify.h)
$(KEM_FRODO1344_OBJS): $(KEM_FRODO1344_HEADERS) $(addprefix src/, kem.c noise.c util.c)

KEM_FROST384_OBJS := $(addprefix objs/, frost384.o util.o)
KEM_FROST384_HEADERS := $(addprefix src/, api_frost384.h config.h frost_macrify.h frost_u32_core.h)
$(KEM_FROST384_OBJS): $(KEM_FROST384_HEADERS) $(addprefix src/, kem_u32.c noise_u32.c frost_macrify_u32.c util.c)

KEM_FROST512_OBJS := $(addprefix objs/, frost512.o util.o)
KEM_FROST512_HEADERS := $(addprefix src/, api_frost512.h config.h frost_macrify.h frost_u32_core.h)
$(KEM_FROST512_OBJS): $(KEM_FROST512_HEADERS) $(addprefix src/, kem_u32.c noise_u32.c frost_macrify_u32.c util.c)

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

ifndef SHAKEx4_OBJS
objs/sha3/fips202x4.o: ../common/sha3/fips202x4.c ../common/sha3/fips202x4.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/sha3/fips202x4.c -o objs/sha3/fips202x4.o

objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o: ../common/sha3/keccak4x/KeccakP-1600-times4-SIMD256.c ../common/sha3/keccak4x/KeccakP-1600-times4-SnP.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/sha3/keccak4x/KeccakP-1600-times4-SIMD256.c -o objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o

SHAKEx4_OBJS := objs/sha3/fips202x4.o objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o
endif

lib128: $(KEM_FRODO640_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf frost128
	mkdir frost128
	$(AR) frost128/libfrost.a $^
	$(RANLIB) frost128/libfrost.a

lib192: $(KEM_FRODO976_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf frost192
	mkdir frost192
	$(AR) frost192/libfrost.a $^
	$(RANLIB) frost192/libfrost.a

lib256: $(KEM_FRODO1344_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf frost256
	mkdir frost256
	$(AR) frost256/libfrost.a $^
	$(RANLIB) frost256/libfrost.a

lib384: $(KEM_FROST384_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf frost384
	mkdir frost384
	$(AR) frost384/libfrost.a $^
	$(RANLIB) frost384/libfrost.a

lib512: $(KEM_FROST512_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf frost512
	mkdir frost512
	$(AR) frost512/libfrost.a $^
	$(RANLIB) frost512/libfrost.a

tests: lib128 lib192 lib256 lib384 lib512 tests/ds_benchmark.h
	$(CC) $(CFLAGS) -L./frost128 tests/test_KEM128.c -lfrost $(LDFLAGS) -o frost128/test_KEM $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost192 tests/test_KEM192.c -lfrost $(LDFLAGS) -o frost192/test_KEM $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost256 tests/test_KEM256.c -lfrost $(LDFLAGS) -o frost256/test_KEM $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost384 tests/test_KEM384.c -lfrost $(LDFLAGS) -o frost384/test_KEM $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost512 tests/test_KEM512.c -lfrost $(LDFLAGS) -o frost512/test_KEM $(ARM_SETTING)

lib128_for_KATs: $(KEM_FRODO640_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	@mkdir -p frost128
	$(AR) frost128/libfrost_for_testing.a $^
	$(RANLIB) frost128/libfrost_for_testing.a

lib192_for_KATs: $(KEM_FRODO976_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	@mkdir -p frost192
	$(AR) frost192/libfrost_for_testing.a $^
	$(RANLIB) frost192/libfrost_for_testing.a

lib256_for_KATs: $(KEM_FRODO1344_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	@mkdir -p frost256
	$(AR) frost256/libfrost_for_testing.a $^
	$(RANLIB) frost256/libfrost_for_testing.a

lib384_for_KATs: $(KEM_FROST384_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	@mkdir -p frost384
	$(AR) frost384/libfrost_for_testing.a $^
	$(RANLIB) frost384/libfrost_for_testing.a

lib512_for_KATs: $(KEM_FROST512_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	@mkdir -p frost512
	$(AR) frost512/libfrost_for_testing.a $^
	$(RANLIB) frost512/libfrost_for_testing.a

KATS: lib128_for_KATs lib192_for_KATs lib256_for_KATs lib384_for_KATs lib512_for_KATs
	@mkdir -p frost128/KAT frost192/KAT frost256/KAT frost384/KAT frost512/KAT
ifeq "$(GENERATION_A)" "SHAKE128"
	$(CC) $(CFLAGS) -L./frost128 tests/PQCtestKAT_kem128_shake.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost128/PQCtestKAT_kem_shake $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost192 tests/PQCtestKAT_kem192_shake.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost192/PQCtestKAT_kem_shake $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost256 tests/PQCtestKAT_kem256_shake.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost256/PQCtestKAT_kem_shake $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost384 tests/PQCtestKAT_kem384_shake.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost384/PQCtestKAT_kem_shake $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost512 tests/PQCtestKAT_kem512_shake.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost512/PQCtestKAT_kem_shake $(ARM_SETTING)
else
	$(CC) $(CFLAGS) -L./frost128 tests/PQCtestKAT_kem128.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost128/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost192 tests/PQCtestKAT_kem192.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost192/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost256 tests/PQCtestKAT_kem256.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost256/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost384 tests/PQCtestKAT_kem384.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost384/PQCtestKAT_kem $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./frost512 tests/PQCtestKAT_kem512.c tests/rng.c -lfrost_for_testing $(LDFLAGS) -o frost512/PQCtestKAT_kem $(ARM_SETTING)
endif

size_test:
	$(CC) $(CFLAGS) tests/test_sizes.c -o test_sizes $(LDFLAGS) $(ARM_SETTING)
	./test_sizes

check: tests size_test

test128:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 frost128/test_KEM
else
	frost128/test_KEM
endif

test192:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 frost192/test_KEM
else
	frost192/test_KEM
endif

test256:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 frost256/test_KEM
else
	frost256/test_KEM
endif

test384:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 frost384/test_KEM
else
	frost384/test_KEM
endif

test512:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 frost512/test_KEM
else
	frost512/test_KEM
endif

clean:
	rm -rf objs *.req frost128 frost192 frost256 frost384 frost512 test_sizes
	find . -name .DS_Store -type f -delete

prettyprint:
	astyle --style=java --indent=tab --pad-header --pad-oper --align-pointer=name --align-reference=name --suffix=none src/*.h src/*/*.h src/*/*.c
