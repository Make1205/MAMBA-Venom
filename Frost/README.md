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


## Reference u16 streaming multiplication

For `OPT_LEVEL=REFERENCE`, Frost-128/192/256 default to a u16 streaming `A^T*R` traversal in the internal Reference streaming matrix-multiplication helper. This generates each public `A` row in the same byte order as the materialized reference path, accumulates it into the `s' * A + e` result, and avoids full `N*N` `A` materialization for encapsulation/re-encryption.

`FROST_U16_MATERIALIZED_A_MATMUL=1` forces the old materialized-`A` reference u16 path for verification and regression testing. The fallback is intended to preserve byte-for-byte KAT comparisons while the streaming traversal remains the default reference implementation.

This reference-only switch does not replace or affect the FAST `avx2_u16` path used by Frost-128/192/256. Frost-384/512 FAST builds use the `u32_full_shake4x` backend.
