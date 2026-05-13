Algorithm instance: Frost-192
Functionality: KEM
Implementation type: Reference
Public key bytes: 9624
Secret key bytes: 11432
Ciphertext bytes: 9688
Shared secret bytes: 24
Required compiler: gcc/clang (C99 or later)
Required instruction set: none (portable reference C)
Build command: make clean && make
KAT command: make KAT && ./KAT_KEM
Source file summary:
- KEM_AlgorithmInstance.[ch]: API_PKC KEM interface to Frost-192.
- randombytes_api.c: API_PKC DRNG-backed randombytes() wrapper.
- KAT_KEM.c, drng.[ch], auxfunc.[ch]: API_PKC template files.
- Frost/src/frost192.c + dependencies from Frost/common: original Frost reference path.
Notes:
- This implementation is for Reference_Implementation.
- Current cryptographic hash/XOF path uses original Frost SHAKE implementation.
