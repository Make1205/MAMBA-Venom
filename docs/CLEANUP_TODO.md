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

Completed: moved eFrost/ to `legacy/eFrost/` for provenance-only retention because it is not a current formal scheme.

## Phase 3A

Completed: renamed low-risk internal helpers such as frost_pack, frost_unpack,
frost_sample_n, frost_add, frost_sub, frost_key_encode, and frost_key_decode.

## Phase 3B

Completed: renamed matrix and dither helpers such as frost_mul_add_as_plus_e,
frost_mul_add_sa_plus_e, frost_mul_bs, frost_mul_add_sb_plus_e,
frost_expand_dither_local, frost_quantize_dithered_profile, and
frost_reconstruct_dithered_profile.

## Phase 4

Completed: final identity audit, source/public wording provenance cleanup, KAT, correctness, and benchmark validation.
