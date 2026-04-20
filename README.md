Venom: Plain-LWE KEM with Public Double-Dither Quantization
===========================================================

`Venom` is a C/Python implementation repository for a plain-LWE key encapsulation mechanism.
The implemented core mechanism uses **public two-layer dither quantization** (双层公开抖动量化),
including the ephemeral variant in `eVenom`.

## Security level variants

- **Venom-1** (128-bit class target)
- **Venom-3** (192-bit class target)
- **Venom-5** (256-bit class target)

Each level supports matrix generation with AES128 or SHAKE128 in the current codebase.

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

- Email: `your-email@example.com` (请替换为你的实际邮箱)
