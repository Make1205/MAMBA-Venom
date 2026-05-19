MAMBA-Frost: Plain-LWE KEM with Public Dither Quantization
=============================================================================

`MAMBA-Frost` / `Frost.KEM` is a plain-LWE key encapsulation mechanism based on
public dither quantization.

The active implementation is located in [`Frost/`](Frost/).
Default builds, correctness tests, KAT generation, and benchmark scripts use this
directory.

## Security level variants

The implementation provides five parameter profiles:

- `MAMBA-Frost-128`
- `MAMBA-Frost-192`
- `MAMBA-Frost-256`
- `MAMBA-Frost-384`
- `MAMBA-Frost-512`

The primary parameter table below lists the first three profiles.
The 384-bit and 512-bit profiles are also supported by the C implementation and
use the 32-bit backend.

| Variant | n | m | ell | qbits | eta_s | eta_r | b_msg | t_pk | t_u | t_v | pk bytes | ct bytes | sk bytes | ss bytes | log2 DFR | Bit Sec. |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| MAMBA-Frost-128 | 512 | 512 | 8 | 15 | 2 | 2 | 2 | 10 | 10 | 8 | 5152 | 5216 | 6752 | 16 | -131.79 | 131.85 |
| MAMBA-Frost-192 | 920 | 920 | 8 | 16 | 1 | 1 | 3 | 12 | 11 | 7 | 11072 | 10208 | 12976 | 24 | -217.72 | 194.47 |
| MAMBA-Frost-256 | 1288 | 1288 | 8 | 16 | 1 | 1 | 4 | 13 | 13 | 7 | 16776 | 16832 | 19416 | 32 | -329.40 | 257.08 |

## Public matrix expansion backend

The default build uses `MATRIX_A_BACKEND=AES128`.
In this mode, the public matrix `A` is expanded from the public seed `seed_A`
with AES-128-ECB.

The optional `MATRIX_A_BACKEND=SHAKE128` path is a test backend.
It changes only public matrix expansion and leaves the rest of the KEM logic
unchanged.

## Repository contents

- [`Frost/`](Frost/): active `MAMBA-Frost` implementation, tests, KAT targets,
  and benchmark scripts.
- [`common/`](common/): shared AES, SHA3, and randomness utilities used by the C
  build.
- [`Makefile`](Makefile): root build entry point that forwards to `Frost/`.

## Build

From the repository root, run:

    make clean
    make

A successful build also runs the size test and prints:

    Frost size test PASSED

The root Makefile forwards to the active implementation under `Frost/`.

## Correctness tests

To run the default correctness test suite from the repository root, use:

    make check

To run the size test only, use:

    make size_test

The same tests can be run directly inside `Frost/`:

    cd Frost
    make clean
    make check
    make size_test

The implementation also provides per-level correctness tests:

    cd Frost
    make test128
    make test192
    make test256
    make test384
    make test512

Each per-level test performs repeated key generation, encapsulation, and
decapsulation checks.
A successful run prints:

    Tests PASSED. All session keys matched.

## KAT generation and verification

KAT support is provided under `Frost/`.

Build the KAT executables with:

    cd Frost
    make clean
    make KATS

This builds one `PQCtestKAT_kem` executable for each parameter profile:

    frost128/PQCtestKAT_kem
    frost192/PQCtestKAT_kem
    frost256/PQCtestKAT_kem
    frost384/PQCtestKAT_kem
    frost512/PQCtestKAT_kem

Run the KAT executables as follows:

    cd Frost/frost128 && ./PQCtestKAT_kem
    cd ../frost192 && ./PQCtestKAT_kem
    cd ../frost256 && ./PQCtestKAT_kem
    cd ../frost384 && ./PQCtestKAT_kem
    cd ../frost512 && ./PQCtestKAT_kem

A successful KAT run prints:

    Known Answer Tests PASSED.

The KAT runs generate response files under the corresponding `KAT/` directories.
For example:

    Frost/frost128/KAT/PQCkemKAT_6752.rsp
    Frost/frost192/KAT/PQCkemKAT_12976.rsp
    Frost/frost256/KAT/PQCkemKAT_19416.rsp
    Frost/frost384/KAT/PQCkemKAT_41440.rsp
    Frost/frost512/KAT/PQCkemKAT_67680.rsp

The generated KAT files and temporary build products can be removed with:

    cd Frost
    make clean

## Benchmarking

The benchmark script is located at:

    Frost/scripts/bench_levels_ref_avx2.sh

Run it from the `Frost/` directory:

    cd Frost
    ./scripts/bench_levels_ref_avx2.sh ./bench.csv

A successful benchmark run prints:

    [done] Benchmark complete. CSV written to ./bench.csv

The output file `bench.csv` contains the measured cycle counts for the available
reference and optimized build paths.

Remove benchmark output and generated build products with:

    rm -f bench.csv
    make clean

## Clean build tree

To remove generated executables, object files, KAT outputs, and temporary build
directories, run:

    make clean

or directly inside the implementation directory:

    cd Frost
    make clean
