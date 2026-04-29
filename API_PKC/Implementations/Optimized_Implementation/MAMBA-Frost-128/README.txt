Algorithm instance: Frost-128
Functionality: KEM
Implementation type: Optimized
Public key bytes: 7072
Secret key bytes: 9056
Ciphertext bytes: 6480
Shared secret bytes: 16
Required compiler: gcc/clang (C99 or later)
Required instruction set: AVX2 + AES-NI + SSE2
Build command: make clean && make
KAT command: make KAT && ./KAT_KEM
Source file summary:
- KEM_AlgorithmInstance.[ch]: API_PKC KEM interface to Frost-128.
- randombytes_api.c: API_PKC DRNG-backed randombytes() wrapper.
- KAT_KEM.c, drng.[ch], auxfunc.[ch]: API_PKC template files.
- Frost/src/venom128.c + dependencies from Frost/common: optimized AVX2 path.
Notes:
- Optimized implementation requires AVX2-capable CPU.
- API_PKC auxiliary files are included.
- The current Frost optimized path still uses the existing Frost SHAKE/XOF implementation internally.
- A later migration step will route SHAKE/XOF through auxfunc wrappers.
