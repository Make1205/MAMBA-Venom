# MAMBA-Frost identity cleanup TODO

This file tracks staged cleanup work for legacy artifacts and inherited internal
names. These items are not part of the current default build, KAT, benchmark, or
paper-data workflow, which is centered on `Frost/`.

## Phase 1B

Move or remove stale Frost/KAT upstream FrodoKEM .rsp artifacts.

## Phase 1C

Move Frost/python3 old FrodoKEM reference tooling to legacy/provenance-only.

## Phase 1D

Move Frost/VisualStudio old FrodoKEM project files to legacy or mark unsupported.

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
