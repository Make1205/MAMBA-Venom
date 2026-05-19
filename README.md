MAMBA-Frost / Frost.KEM: Plain-LWE KEM with Public Double-Dither Quantization
=============================================================================

`MAMBA-Frost` / `Frost.KEM` is a plain-LWE key encapsulation mechanism whose
current main implementation lives in [`Frost/`](Frost/). The implemented core
mechanism uses **public two-layer dither quantization**.

Default builds, KAT generation, benchmark orchestration, and paper-data runs are
intended to use [`Frost/`](Frost/) as the active implementation directory.
Historical artifacts outside that path are cleanup candidates and are not part
of the default build, KAT, benchmark, or paper-data workflow.

## Security level variants

- **Frost-128** (implemented)
- **Frost-192** (implemented)
- **Frost-256** (implemented)
- **Frost-384** (implemented; repository extension parameters retained)
- **Frost-512** (implemented; repository extension parameters retained)

Current C core supports all five `MAMBA-Frost-128/192/256/384/512` profiles.
`Frost-384/512` keep the repository extension parameters and use the 32-bit backend.

| Variant | n | m | ell | qbits | eta_s | eta_r | b_msg | t_pk | t_u | t_v | pk bytes | ct bytes | sk bytes | ss bytes | log2 DFR | Bit Sec. |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| MAMBA-Frost-128 | 512 | 512 | 8 | 15 | 2 | 2 | 2 | 10 | 10 | 8 | 5152 | 5216 | 6752 | 16 | -131.79 | 131.85 |
| MAMBA-Frost-192 | 920 | 920 | 8 | 16 | 1 | 1 | 3 | 12 | 11 | 7 | 11072 | 10208 | 12976 | 24 | -217.72 | 194.47 |
| MAMBA-Frost-256 | 1288 | 1288 | 8 | 16 | 1 | 1 | 4 | 13 | 13 | 7 | 16776 | 16832 | 19416 | 32 | -329.40 | 257.08 |
| MAMBA-Frost-384 | 2176 | 2176 | 8 | 18 | 3 | 3 | 6 | 16 | 15 | 13 | 34848 | 32776 | 41440 | 48 | — | — |
| MAMBA-Frost-512 | 3072 | 3072 | 8 | 20 | 4 | 4 | 8 | 18 | 18 | 11 | 55328 | 55416 | 67680 | 64 | — | — |


## Public matrix expansion backend

In the active `Frost/` implementation, default builds use
`MATRIX_A_BACKEND=AES128`: Frost-128, Frost-192, and Frost-256 all expand the
public matrix `A` from the public `seed_A` with AES-128-ECB. The optional
`MATRIX_A_BACKEND=SHAKE128` path is a Frost-SHAKE test backend that replaces
only public matrix expansion with SHAKE128.

## Repository contents

- [`Frost/`](Frost/): current `MAMBA-Frost` / `Frost.KEM` implementation, tests,
  KAT generation targets, and benchmark scripts.
- [`common/`](common/): shared AES/SHA3/random utilities used by the C build.
- [`docs/CLEANUP_TODO.md`](docs/CLEANUP_TODO.md): staged identity-cleanup follow-up
  items for legacy artifacts that are not part of the current default workflow.
- [`LICENSE`](LICENSE): license text.

## Provenance and license notes

The implementation inherits parts of an unstructured LWE KEM code framework and
retains the corresponding license notices. Legacy upstream artifacts and tooling
that still need separate cleanup are tracked in [`docs/CLEANUP_TODO.md`](docs/CLEANUP_TODO.md)
so their provenance can be preserved while the public project identity remains
focused on `MAMBA-Frost` / `Frost.KEM`.

## Paper

Paper metadata is omitted in this anonymous submission package.

## Contact

Contact details are omitted in this anonymous submission package.
