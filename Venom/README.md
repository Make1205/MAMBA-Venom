MAMBA-Venom (Standard)
======================

This directory contains the standard `MAMBA-Venom` implementation in the same C code framework.

## Variants

- `Venom-128` (implemented)
- `Venom-192` (implemented)
- `Venom-256` (implemented)
- `Venom-384` (planned)
- `Venom-512` (planned)

## Build

```sh
make
```

Current generated folders and binaries remain tied to the existing Makefile target names
(legacy target directory names in the current Makefile) for compatibility with the current test/build harness.

## Benchmark script (Venom-128/192/256, ref vs fast/AVX2 build)

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
- `AVX2` (implemented as `OPT_LEVEL=FAST`)

and write a CSV with per-operation timing/cycle summary.

If you want to force AVX2 for Level-192/256 as well (experimental), run:

```sh
FORCE_L256_AVX2=1 ./scripts/bench_levels_ref_avx2.sh
```

When a benchmark run crashes/fails, the script keeps running and writes a `run_failed` row with failure status in the CSV.
