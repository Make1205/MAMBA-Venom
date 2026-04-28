Algorithm instance: Venom-512
Functionality: KEM
Implementation type: Reference
Public key bytes: 55328
Secret key bytes: 67680
Ciphertext bytes: 55416
Shared secret bytes: 64
Required compiler: gcc/clang (C99 or later)
Required instruction set: none (portable reference C)
Build command: make clean && make
KAT command: make KAT && ./KAT_KEM
Source file summary:
- KEM_AlgorithmInstance.[ch]: API_PKC KEM interface to Venom-512.
- randombytes_api.c: API_PKC DRNG-backed randombytes() wrapper.
- KAT_KEM.c, drng.[ch], auxfunc.[ch]: API_PKC template files.
- Venom/src/venom512.c + dependencies from Venom/common: original Venom reference path.
Notes:
- This implementation is for Reference_Implementation.
- Current cryptographic hash/XOF path uses original Venom SHAKE implementation.
