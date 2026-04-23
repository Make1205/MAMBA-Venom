MAMBA-Venom (Standard)
======================

This directory contains the standard `MAMBA-Venom` implementation in the same C code framework.

## Variants

- `MAMBA-Venom-1`
- `MAMBA-Venom-3`
- `MAMBA-Venom-5`

## Build

```sh
make
```

Current generated folders and binaries remain tied to the existing Makefile target names
(legacy target directory names in the current Makefile) for compatibility with the current test/build harness.

## Benchmark script (Level-1/3/5, ref vs fast/AVX2 build)

Run:

```sh
./scripts/bench_levels_ref_avx2.sh
```

Optional output path:

```sh
./scripts/bench_levels_ref_avx2.sh ./bench.csv
```

The script will build and benchmark all three levels for:

- `OPT_LEVEL=REFERENCE`
- `OPT_LEVEL=FAST` (AVX2-capable build settings on AMD64)

and write a CSV with per-operation timing/cycle summary.
