Venom: Plain-LWE KEM with Public Double-Dither Quantization
===========================================================

`Venom` is a C/Python implementation repository for a plain-LWE key encapsulation mechanism.
The implemented core mechanism uses **public two-layer dither quantization**,
including the ephemeral variant in `eVenom`.

## Security level variants

- **Venom-128** (implemented)
- **Venom-192** (implemented)
- **Venom-256** (implemented)
- **Venom-384** (parameter extension target, not yet implemented in C core)
- **Venom-512** (parameter extension target, not yet implemented in C core)

Current C core fully supports `Venom-128/192/256` for both REF and AVX2 build workflows.

## Repository contents

- [`common/`](common/): shared AES/SHA3/random utilities.
- [`Venom/`](Venom/): standard variant implementation and tests.
- [`eVenom/`](eVenom/): ephemeral variant implementation and tests.
- [`LICENSE`](LICENSE): license text.

## Paper

```bibtex
@misc{cryptoeprint:2024/714,
      author = {Shanxiang Lyu and Ling Liu and Cong Ling},
      title = {Learning With Quantization: A Ciphertext Efficient Lattice Problem with Tight Security Reduction from {LWE}},
      howpublished = {Cryptology {ePrint} Archive, Paper 2024/714},
      year = {2024},
      url = {https://eprint.iacr.org/2024/714}
}
```

## Contact

- Email: `make2024@stu2024.jnu.edu.cn`
