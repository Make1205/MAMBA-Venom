MAMBA-Venom: Plain-LWE KEM with Public Double-Dither Quantization
=================================================================

`MAMBA-Venom` is a C/Python implementation repository for a plain-LWE key encapsulation mechanism.
The implemented core mechanism uses **public two-layer dither quantization** (双层公开抖动量化),
including the ephemeral variant in `eMAMBA-Venom`.

## Security level variants

- **Venom-1** (128-bit class target)
- **Venom-3** (192-bit class target)
- **Venom-5** (256-bit class target)

Each level supports matrix generation with AES128 or SHAKE128 in the current codebase.

## Repository contents

- [`common/`](common/): shared AES/SHA3/random utilities.
- [`MAMBA-Venom/`](MAMBA-Venom/): standard variant implementation and tests.
- [`eMAMBA-Venom/`](eMAMBA-Venom/): ephemeral variant implementation and tests.
- [`LICENSE`](LICENSE): license text.

## Notes for current stage

- Documentation and naming are aligned to `MAMBA-Venom`.
- The deprecated in-repo estimator scripts are removed in this stage.
- No new unimplemented functionality is declared in this README.
