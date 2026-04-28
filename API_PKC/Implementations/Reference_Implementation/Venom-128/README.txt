Algorithm instance: Venom-128
Functionality: KEM
Implementation type: Reference
Public key bytes: 7072
Secret key bytes: 9056
Ciphertext bytes: 6480
Shared secret bytes: 16
Required compiler: gcc/clang (C99 or later)
Required instruction set: none (portable reference C)
Build command: make clean && make
KAT command: make KAT && ./KAT_KEM
Source file summary:
- KEM_AlgorithmInstance.[ch]: API_PKC KEM interface to Venom-128.
- randombytes_api.c: API_PKC DRNG-backed randombytes() wrapper.
- KAT_KEM.c, drng.[ch], auxfunc.[ch]: API_PKC template files.
- Venom/src/venom128.c + dependencies from Venom/common: original Venom reference path.
Notes:
- This implementation is for Reference_Implementation.
- Current cryptographic hash/XOF path uses original Venom SHAKE implementation.
