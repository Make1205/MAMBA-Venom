#!/usr/bin/env bash
set -euo pipefail
OUT_CSV=${1:-/tmp/frost_profile_breakdown.csv}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FROST_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
ONLY_LEVEL=${ONLY_LEVEL:-}
ONLY_MODE=${ONLY_MODE:-}
RUN_REFERENCE=${RUN_REFERENCE:-1}
RUN_AVX2=${RUN_AVX2:-1}
FROST_U16_STREAMING_MATMUL=${FROST_U16_STREAMING_MATMUL:-0}
PROFILE_LEVELS=${PROFILE_LEVELS:-128 192 256}
PROFILE_ITERS=${PROFILE_ITERS:-10}
PROFILE_BENCH_SECONDS=${PROFILE_BENCH_SECONDS:-1}
PROFILE_TIMEOUT=${PROFILE_TIMEOUT:-600}

level_bin(){ case "$1" in 128) echo frost128/test_KEM;;192) echo frost192/test_KEM;;256) echo frost256/test_KEM;;384) echo frost384/test_KEM;;512) echo frost512/test_KEM;;*) return 1;; esac; }
backend_tag(){
  local mode="$1" level="$2"
  if [[ "$mode" == "REFERENCE" ]]; then
    echo ref
  elif [[ "$level" == "128" ]]; then
    echo avx2_u16
  elif [[ "$level" == "192" || "$level" == "256" ]]; then
    if [[ "${FORCE_USE_AVX2_FOR_L256:-0}" == "1" ]]; then echo avx2_u16_forced; else echo fast_u16_no_avx2; fi
  else
    echo u32_full_shake4x
  fi
}

audit_backend(){
  local mode="$1" level="$2" backend="$3" force="${FORCE_USE_AVX2_FOR_L256:-0}" generation="${GENERATION_A:-AES128}"
  local use_reference=0 use_avx2=0 use_avx2_u32=0 effective=""
  if [[ "$mode" == "REFERENCE" ]]; then
    use_reference=1; effective="frost_macrify_reference.c"
  elif [[ "$level" == "128" ]]; then
    use_avx2=1; use_avx2_u32=1; effective="frost_macrify.c USE_AVX2 u16 path"
  elif [[ "$level" == "192" || "$level" == "256" ]]; then
    use_avx2_u32=1
    if [[ "$force" == "1" ]]; then use_avx2=1; effective="frost_macrify.c forced USE_AVX2 u16 path"; else use_avx2=0; effective="frost_macrify.c FAST/RWCF u16 path (USE_AVX2 undefined in level file)"; fi
  else
    use_avx2=1; use_avx2_u32=1; effective="frost_macrify_u32.c u32_full_shake4x path"
  fi
  echo "[backend-audit] level=$level mode=$mode backend_tag=$backend USE_REFERENCE=$use_reference USE_AVX2=$use_avx2 FORCE_USE_AVX2_FOR_L256=$force USE_AVX2_U32=$use_avx2_u32 GENERATION_A=$generation effective=$effective FROST_U16_STREAMING_MATMUL=$FROST_U16_STREAMING_MATMUL" >&2
}

modes=()
if [[ -n "$ONLY_MODE" ]]; then
  modes=("$([[ "$ONLY_MODE" == "AVX2" ]] && echo FAST || echo "$ONLY_MODE")")
else
  [[ "$RUN_REFERENCE" == "1" ]] && modes+=("REFERENCE")
  [[ "$RUN_AVX2" == "1" ]] && modes+=("FAST")
fi
read -r -a levels <<< "$PROFILE_LEVELS"
[[ -n "$ONLY_LEVEL" ]] && levels=("$ONLY_LEVEL")

printf 'scheme,level,backend,operation,stage,cycles_mean,iterations\n' > "$OUT_CSV"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

for mode in "${modes[@]}"; do
  echo "[profile] building $mode" >&2
  make -C "$FROST_DIR" clean >/dev/null
  if [[ "$mode" == "REFERENCE" ]]; then
    make -C "$FROST_DIR" OPT_LEVEL=REFERENCE FROST_U16_STREAMING_MATMUL="$FROST_U16_STREAMING_MATMUL" EXTRA_CFLAGS='-O3 -DPROFILE_ALL_LEVELS' tests >/dev/null
  else
    make -C "$FROST_DIR" OPT_LEVEL=FAST FROST_U16_STREAMING_MATMUL="$FROST_U16_STREAMING_MATMUL" EXTRA_CFLAGS='-O3 -DPROFILE_ALL_LEVELS' tests >/dev/null
  fi
  for level in "${levels[@]}"; do
    backend=$(backend_tag "$mode" "$level")
    audit_backend "$mode" "$level" "$backend"
    bin=$(level_bin "$level")
    log="$tmpdir/${mode}_${level}.log"
    echo "[profile] mode=$mode level=$level iterations=$PROFILE_ITERS bench_seconds=$PROFILE_BENCH_SECONDS" >&2
    timeout "$PROFILE_TIMEOUT" env PROFILE_ALL_LEVELS=1 FROST_KEM_TEST_ITERATIONS="$PROFILE_ITERS" FROST_KEM_BENCH_SECONDS="$PROFILE_BENCH_SECONDS" "$FROST_DIR/$bin" >"$log" 2>&1
    awk -v scheme=Frost -v level="$level" -v backend="$backend" '
      /^\[profile-all\]/ {
        api="";
        for (i=1; i<=NF; i++) {
          split($i, kv, "=");
          if (kv[1] == "api") { api=kv[2]; break; }
        }
        for (i=1; i<=NF; i++) {
          split($i, kv, "=");
          if (kv[1] ~ /^\[profile-all\]$/ || kv[1] == "level" || kv[1] == "api") continue;
          key=api SUBSEP kv[1]; sums[key]+=kv[2]; counts[key]++;
        }
      }
      END {
        for (key in sums) {
          split(key, parts, SUBSEP);
          printf "%s,%s,%s,%s,%s,%.0f,%d\n", scheme, level, backend, parts[1], parts[2], sums[key]/counts[key], counts[key];
        }
      }
    ' "$log" | sort -t, -k4,4 -k5,5 >> "$OUT_CSV"
  done
done

echo "[profile] wrote $OUT_CSV" >&2
