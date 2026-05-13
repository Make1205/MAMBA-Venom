MAMBA-Frost (Standard)
======================

This directory contains the standard `MAMBA-Frost` implementation in the same C code framework.

## Variants

- `Frost-128` (implemented)
- `Frost-192` (implemented)
- `Frost-256` (implemented)
- `Frost-384` (32-bit backend: ref + AVX2-u32 streaming)
- `Frost-512` (32-bit backend: ref + AVX2-u32 streaming)

## Build

```sh
make
```

The Makefile builds all five `MAMBA-Frost` profiles and emits `frost128` through `frost512` build directories.

## Benchmark script (Frost-128/192/256, ref vs fast/AVX2 build)

Run:

```sh
./scripts/bench_levels_ref_avx2.sh
```

Optional output path:

```sh
./scripts/bench_levels_ref_avx2.sh ./bench.csv
```

The script will build and benchmark all five levels for:

- `OPT_LEVEL=REFERENCE`
- `AVX2` (implemented as `OPT_LEVEL=FAST`)

and write a CSV with per-operation timing/cycle summary.


When a benchmark run crashes/fails, the script keeps running and writes a `run_failed` row with failure status in the CSV.

Environment toggles for benchmark orchestration:

- `RUN_REFERENCE=0|1` (default: `1`)
- `RUN_AVX2=0|1` (default: `1`)
- `ONLY_LEVEL=<128|192|256|384|512>`
- `ONLY_MODE=<REFERENCE|AVX2>`
- `PROFILE_U32=0|1` (enable u32 profile logs for level 384/512)

CSV naming conventions:

- `backend`: `ref` for `REFERENCE`, `avx2` for `AVX2`
- `notes`:
  - REFERENCE: `u16` for 128/192/256, `u32` for 384/512
  - AVX2: `u16` for 128/192/256, `u32_full_shake4x` for 384/512
