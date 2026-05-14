eMAMBA-Frost (Ephemeral)
========================

This directory provides the ephemeral `MAMBA-Frost` implementation with the same build/test
framework and file layout as the parent codebase.

## Mechanism status in this directory

- Uses plain-LWE framework.
- Uses **public two-layer dither quantization** path in KEM operations.
- Keeps the existing build flow, tests, and API structure with minimal surface change.

## Variants

- `eMAMBA-Frost-1`
- `eMAMBA-Frost-3`
- `eMAMBA-Frost-5`

## Build and test

```sh
make
```

Current generated folders and binaries in this directory are still produced by the existing
Makefile targets (legacy target directory names in the current Makefile) to keep build compatibility in this step.
