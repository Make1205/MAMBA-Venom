Algorithm instance: Venom-192
Functionality: KEM
Implementation type: Reference
Public key bytes: 11744
Secret key bytes: 14736
Ciphertext bytes: 11792
Shared secret bytes: 24
Required compiler: gcc/clang (C99 or later)
Required instruction set: none (portable reference C)
Build command: make clean && make
KAT command: make KAT && ./KAT_KEM
Source file summary:
- KEM_AlgorithmInstance.[ch]: API_PKC KEM interface to Venom-192.
- randombytes_api.c: API_PKC DRNG-backed randombytes() wrapper.
- KAT_KEM.c, drng.[ch], auxfunc.[ch]: API_PKC template files.
- Venom/src/venom192.c + dependencies from Venom/common: original Venom reference path.
Notes:
- This implementation is for Reference_Implementation.
- Current cryptographic hash/XOF path uses original Venom SHAKE implementation.
