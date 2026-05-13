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

## Benchmark script (Frost-128/192/256, ref vs FAST build)

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
- `FAST` (implemented as `OPT_LEVEL=FAST`; Frost-128/192/256 use AVX2 u16 intrinsics, while Frost-384/512 use the u32 full SHAKE4x path)

and write a CSV with per-operation timing/cycle summary.


When a benchmark run crashes/fails, the script keeps running and writes a `run_failed` row with failure status in the CSV.

Environment toggles for benchmark orchestration:

- `RUN_REFERENCE=0|1` (default: `1`)
- `RUN_AVX2=0|1` (default: `1`; compatibility name for the FAST build)
- `ONLY_LEVEL=<128|192|256|384|512>`
- `ONLY_MODE=<REFERENCE|FAST>` (`AVX2` is accepted as a compatibility alias for `FAST`)
- `PROFILE_U32=0|1` (enable u32 profile logs for level 384/512)

CSV naming conventions:

- `mode`: `REFERENCE` or `FAST`
- `backend`: true implementation tag, for example `ref`, `avx2_u16` (Frost-128/192/256 FAST), or `u32_full_shake4x` (Frost-384/512 FAST)
- `notes`: mirrors the backend implementation tag for FAST rows and uses `u16`/`u32` for REFERENCE rows


## Experimental u16 streaming multiplication

`FROST_U16_STREAMING_MATMUL=1` enables an experimental reference u16 `A^T*R` streaming path for Frost-128/192/256. It is off by default, preserves KAT byte output, and is intended for profiling cache/materialization effects before any default-path change. It does not replace the FAST AVX2 u16 path.
