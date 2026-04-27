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

Current C core supports `Venom-128/192/256` and now includes a 32-bit reference backend for
`Venom-384/512` (qbits 18/20). For `Venom-384/512`, AVX2 builds explicitly fall back to the
reference backend.

| Variant | n | m | ell | qbits | eta_s | eta_r | b_msg | t_pk | t_u | t_v | pk bytes | ct bytes | sk bytes | ss bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Venom-128 | 640 | 640 | 8 | 15 | 2 | 2 | 2 | 11 | 10 | 6 | 7072 | 6480 | 9056 | 16 |
| Venom-192 | 976 | 976 | 8 | 15 | 2 | 2 | 3 | 12 | 12 | 6 | 11744 | 11792 | 14736 | 24 |
| Venom-256 | 1344 | 1344 | 8 | 16 | 2 | 2 | 4 | 13 | 13 | 8 | 17504 | 17568 | 21600 | 32 |
| Venom-384 | 2176 | 2176 | 8 | 18 | 3 | 3 | 6 | 16 | 15 | 13 | 34848 | 32776 | 41440 | 48 |
| Venom-512 | 3072 | 3072 | 8 | 20 | 4 | 4 | 8 | 18 | 18 | 11 | 55328 | 55416 | 67680 | 64 |

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
