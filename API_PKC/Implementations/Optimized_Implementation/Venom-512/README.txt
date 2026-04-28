Algorithm instance: Venom-512
Functionality: KEM
Implementation type: Optimized
Public key bytes: 55328
Secret key bytes: 67680
Ciphertext bytes: 55416
Shared secret bytes: 64
Required compiler: gcc/clang (C99 or later)
Required instruction set: AVX2 + AES-NI + SSE2
Build command: make clean && make
KAT command: make KAT && ./KAT_KEM
Source file summary:
- KEM_AlgorithmInstance.[ch]: API_PKC KEM interface to Venom-512.
- randombytes_api.c: API_PKC DRNG-backed randombytes() wrapper.
- KAT_KEM.c, drng.[ch], auxfunc.[ch]: API_PKC template files.
- Venom/src/venom512.c + dependencies from Venom/common: optimized u32 AVX2 path.
Notes:
- Optimized implementation requires AVX2-capable CPU.
- Optimized path uses u32_full_shake4x style row-batched streaming backend.
- API_PKC auxiliary files are included.
- The current Venom optimized path still uses the existing Venom SHAKE/XOF implementation internally.
- A later migration step will route SHAKE/XOF through auxfunc wrappers.
