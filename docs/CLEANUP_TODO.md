# MAMBA-Frost identity cleanup TODO

This file tracks staged cleanup work for legacy artifacts and inherited internal
names. These items are not part of the current default build, KAT, benchmark, or
paper-data workflow, which is centered on `Frost/`.

## Phase 1B

Completed: moved stale Frost/KAT upstream FrodoKEM .rsp artifacts to `legacy/upstream-frodo-kat/` for provenance-only retention.

## Phase 1C

Completed: moved Frost/python3 old FrodoKEM reference tooling to `legacy/upstream-python/` for provenance-only retention.

## Phase 1D

Completed: moved Frost/VisualStudio old FrodoKEM project files to `legacy/visualstudio-upstream/` for provenance-only retention as unsupported legacy project files.

## Phase 2

Delete or move eFrost/ to legacy if it is not a current formal scheme.

## Phase 3A

Rename low-risk internal helpers such as frodo_pack, frodo_unpack,
frodo_sample_n, frodo_add, frodo_sub, frodo_key_encode, and frodo_key_decode.

## Phase 3B

Rename matrix and dither helpers such as frodo_mul_add_as_plus_e,
frodo_mul_add_sa_plus_e, frodo_mul_bs, frodo_mul_add_sb_plus_e,
frodo_expand_dither_local, frodo_quantize_dithered_profile, and
frodo_reconstruct_dithered_profile.

## Phase 4

Final identity audit, KAT, correctness, and benchmark.
