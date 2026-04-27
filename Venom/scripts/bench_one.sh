#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MODE="REFERENCE"
LEVEL="384"
REPS="1"
VERBOSE="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --level) LEVEL="$2"; shift 2 ;;
    --reps) REPS="$2"; shift 2 ;;
    --verbose) VERBOSE="1"; shift 1 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done
ONLY_MODE="$MODE" ONLY_LEVEL="$LEVEL" REPS="$REPS" BENCH_VERBOSE="$VERBOSE" "$SCRIPT_DIR/bench_levels_ref_avx2.sh"
