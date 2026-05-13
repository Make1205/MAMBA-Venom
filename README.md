Frost: Plain-LWE KEM with Public Double-Dither Quantization
===========================================================

`Frost` is a C/Python implementation repository for a plain-LWE key encapsulation mechanism.
The implemented core mechanism uses **public two-layer dither quantization**,
including the ephemeral variant in `eFrost`.

## Security level variants

- **Frost-128** (implemented)
- **Frost-192** (implemented)
- **Frost-256** (implemented)
- **Frost-384** (implemented; repository extension parameters retained)
- **Frost-512** (implemented; repository extension parameters retained)

Current C core supports all five `MAMBA-Frost-128/192/256/384/512` profiles.
`Frost-384/512` keep the repository extension parameters and use the 32-bit backend.

| Variant | n | m | ell | qbits | eta_s | eta_r | b_msg | t_pk | t_u | t_v | pk bytes | ct bytes | sk bytes | ss bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| MAMBA-Frost-128 | 512 | 512 | 8 | 15 | 2 | 2 | 2 | 10 | 10 | 8 | 5152 | 5216 | 6752 | 16 |
| MAMBA-Frost-192 | 872 | 872 | 8 | 16 | 1 | 1 | 3 | 11 | 11 | 8 | 9624 | 9688 | 11432 | 24 |
| MAMBA-Frost-256 | 1280 | 1280 | 8 | 16 | 1 | 1 | 4 | 13 | 12 | 7 | 16672 | 15448 | 19296 | 32 |
| MAMBA-Frost-384 | 2176 | 2176 | 8 | 18 | 3 | 3 | 6 | 16 | 15 | 13 | 34848 | 32776 | 41440 | 48 |
| MAMBA-Frost-512 | 3072 | 3072 | 8 | 20 | 4 | 4 | 8 | 18 | 18 | 11 | 55328 | 55416 | 67680 | 64 |

## Repository contents

- [`common/`](common/): shared AES/SHA3/random utilities.
- [`Frost/`](Frost/): standard variant implementation and tests.
- [`eFrost/`](eFrost/): ephemeral variant implementation and tests.
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
