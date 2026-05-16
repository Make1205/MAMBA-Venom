#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FROST_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
OUT_CSV=${1:-"${FROST_DIR}/bench_results_$(date -u +%Y%m%dT%H%M%SZ).csv"}

read -r -a ALL_LEVELS <<< "${BENCH_LEVELS:-128 192 256}"
ONLY_MODE=${ONLY_MODE:-}
ONLY_LEVEL=${ONLY_LEVEL:-}
RUN_REFERENCE=${RUN_REFERENCE:-1}
RUN_AVX2=${RUN_AVX2:-1}
FROST_U16_STREAMING_MATMUL=${FROST_U16_STREAMING_MATMUL:-0}
FROST_U16_MATERIALIZED_A_MATMUL=${FROST_U16_MATERIALIZED_A_MATMUL:-0}
PROFILE_U32=${PROFILE_U32:-0}
REPS=${REPS:-}
MATRIX_A_BACKENDS=${MATRIX_A_BACKENDS:-${MATRIX_A_BACKEND:-AES128}}

source "${SCRIPT_DIR}/frost_profile_sizes.sh"

get_level_env_default(){ local p="$1" l="$2" d="$3" ar="${4:-0}"; local v="${p}_${l}"; local val="${!v:-}"; if [[ "$ar" == "1" && -n "$REPS" ]]; then echo "$REPS"; elif [[ -n "$val" ]]; then echo "$val"; else echo "$d"; fi; }
api_header_for_level(){ case "$1" in 128) echo api_frost128.h;;192) echo api_frost192.h;;256) echo api_frost256.h;;384) echo api_frost384.h;;512) echo api_frost512.h;; esac; }
level_bin(){ case "$1" in 128) echo frost128/test_KEM;;192) echo frost192/test_KEM;;256) echo frost256/test_KEM;;384) echo frost384/test_KEM;;512) echo frost512/test_KEM;; esac; }

get_bench_seconds(){ case "$1" in 128|192|256) get_level_env_default FROST_BENCH_REPS "$1" 1 1;;384) get_level_env_default FROST_BENCH_REPS "$1" 3 1;;512) get_level_env_default FROST_BENCH_REPS "$1" 1 1;; esac; }
get_correct_iters(){ case "$1" in 128|192|256) get_level_env_default FROST_KAT_REPS "$1" 1000 1;;384) get_level_env_default FROST_KAT_REPS "$1" 20 1;;512) get_level_env_default FROST_KAT_REPS "$1" 10 1;; esac; }
get_timeout_secs(){ case "$1" in
128|192) get_level_env_default FROST_TIMEOUT "$1" 120;;
256) get_level_env_default FROST_TIMEOUT "$1" 600;;
384) get_level_env_default FROST_TIMEOUT "$1" 600;;
512) get_level_env_default FROST_TIMEOUT "$1" 1200;;
esac; }

level_params(){ frost_level_params "$1"; }
expected_sizes(){ frost_expected_sizes "$1"; }
query_sizes_from_api(){ local h; h="$(api_header_for_level "$1")"; cpp -dM -include "$FROST_DIR/src/$h" /dev/null | awk '$2=="CRYPTO_PUBLICKEYBYTES"{pk=$3}$2=="CRYPTO_CIPHERTEXTBYTES"{ct=$3}$2=="CRYPTO_SECRETKEYBYTES"{sk=$3}$2=="CRYPTO_BYTES"{ss=$3}END{printf "%s,%s,%s,%s\n",pk,ct,sk,ss}'; }

parse_cycles(){ awk '$1=="Key"&&$2=="generation"{ki=$3;k=(NF>=7?$(NF-1):"")}$1=="KEM"&&$2=="encapsulate"{ei=$3;e=(NF>=7?$(NF-1):"")}$1=="KEM"&&$2=="decapsulate"{di=$3;d=(NF>=7?$(NF-1):"")}END{tot="";if(k!=""&&e!=""&&d!="")tot=k+e+d;it=ki;if(ei>it)it=ei;if(di>it)it=di;printf "%s,%s,%s,%s,%s\n",k,e,d,tot,it}' "$1"; }

backend_tag(){
  local mode="$1" level="$2"
  if [[ "$mode" == "REFERENCE" ]]; then
    echo "ref"
  elif [[ "$level" == "128" ]]; then
    echo "avx2_u16"
  elif [[ "$level" == "192" || "$level" == "256" ]]; then
    echo "avx2_u16"
  else
    echo "u32_full_shake4x"
  fi
}

notes_for_run(){
  local mode="$1" level="$2"
  if [[ "$mode" == "REFERENCE" ]]; then
    [[ "$level" == "384" || "$level" == "512" ]] && echo "u32" || echo "u16"
  else
    backend_tag "$mode" "$level"
  fi
}

audit_backend(){
  local mode="$1" level="$2" backend="$3" matrix_backend="$4"
  local use_reference=0 use_avx2=0 use_avx2_u32=0 force="${FORCE_USE_AVX2_FOR_L256:-0}" effective=""
  local generation="$matrix_backend"
  if [[ "$mode" == "REFERENCE" ]]; then
    use_reference=1
    if [[ "$level" == "384" || "$level" == "512" ]]; then effective="frost_macrify_u32.c reference u32 path"; elif [[ "$FROST_U16_MATERIALIZED_A_MATMUL" == "1" ]]; then effective="frost_macrify_reference.c materialized u16 path"; else effective="frost_macrify_reference.c streaming u16 path"; fi
  elif [[ "$level" == "128" ]]; then
    use_avx2=1
    use_avx2_u32=1
    effective="frost_macrify.c USE_AVX2 u16 path"
  elif [[ "$level" == "192" || "$level" == "256" ]]; then
    use_avx2=1
    use_avx2_u32=1
    effective="frost_macrify.c USE_AVX2 u16 path"
  else
    use_avx2=1
    use_avx2_u32=1
    effective="frost_macrify_u32.c u32_full_shake4x path"
  fi
  echo "[backend-audit] level=$level mode=$mode backend_tag=$backend USE_REFERENCE=$use_reference USE_AVX2=$use_avx2 FORCE_USE_AVX2_FOR_L256=$force USE_AVX2_U32=$use_avx2_u32 MATRIX_A_BACKEND=$generation effective=$effective FROST_U16_STREAMING_MATMUL=$FROST_U16_STREAMING_MATMUL FROST_U16_MATERIALIZED_A_MATMUL=$FROST_U16_MATERIALIZED_A_MATMUL"
}

modes=()
if [[ -n "$ONLY_MODE" ]]; then
  modes=("$([[ "$ONLY_MODE" == "AVX2" ]] && echo FAST || echo "$ONLY_MODE")")
else
  [[ "$RUN_REFERENCE" == "1" ]] && modes+=("REFERENCE")
  [[ "$RUN_AVX2" == "1" ]] && modes+=("FAST")
fi
if [[ ${#modes[@]} -eq 0 ]]; then
  echo "[error] no benchmark mode enabled (RUN_REFERENCE/RUN_AVX2 are both 0)"
  exit 1
fi

levels=("${ALL_LEVELS[@]}")
[[ -n "$ONLY_LEVEL" ]] && levels=("$ONLY_LEVEL")

printf 'scheme,level,mode,implementation_backend,matrix_backend,keygen_cycles,encaps_cycles,decaps_cycles,total_cycles,pk_bytes,ct_bytes,sk_bytes,ss_bytes,iterations,status,notes\n' > "$OUT_CSV"
echo "[info] Output CSV: $OUT_CSV"
echo "[info] Running benchmarks for modes: ${modes[*]}"
echo "[info] Matrix A backends: $MATRIX_A_BACKENDS"

echo "[info] PROFILE_U32=$PROFILE_U32"
echo "[info] FROST_U16_STREAMING_MATMUL=$FROST_U16_STREAMING_MATMUL FROST_U16_MATERIALIZED_A_MATMUL=$FROST_U16_MATERIALIZED_A_MATMUL"

read -r -a matrix_backends <<< "$MATRIX_A_BACKENDS"
for matrix_backend in "${matrix_backends[@]}"; do
  for mode in "${modes[@]}"; do
    echo "[info] ===== Building matrix_backend=$matrix_backend mode=$mode ====="
    make -C "$FROST_DIR" clean >/dev/null
    if [[ "$mode" == "REFERENCE" ]]; then
      make -C "$FROST_DIR" OPT_LEVEL=REFERENCE MATRIX_A_BACKEND="$matrix_backend" FROST_U16_STREAMING_MATMUL="$FROST_U16_STREAMING_MATMUL" FROST_U16_MATERIALIZED_A_MATMUL="$FROST_U16_MATERIALIZED_A_MATMUL" tests >/dev/null
    else
      make -C "$FROST_DIR" OPT_LEVEL=FAST MATRIX_A_BACKEND="$matrix_backend" FROST_U16_STREAMING_MATMUL="$FROST_U16_STREAMING_MATMUL" FROST_U16_MATERIALIZED_A_MATMUL="$FROST_U16_MATERIALIZED_A_MATMUL" tests >/dev/null
    fi

    for level in "${levels[@]}"; do
    bin=$(level_bin "$level"); timeout_s=$(get_timeout_secs "$level"); correct_iters=$(get_correct_iters "$level"); bench_seconds=$(get_bench_seconds "$level")
    backend="$(backend_tag "$mode" "$level")"
    audit_backend "$mode" "$level" "$backend" "$matrix_backend"
    notes="$(notes_for_run "$mode" "$level")"

    echo "[param-check] level=$level $(level_params "$level")"
    IFS=',' read -r pkb ctb skb ssb <<< "$(query_sizes_from_api "$level")"
    IFS=',' read -r exp_pk exp_ct exp_sk exp_ss <<< "$(expected_sizes "$level")"
    echo "[param-check] level=$level pk_bytes=$pkb ct_bytes=$ctb sk_bytes=$skb ss_bytes=$ssb"
    if [[ "$pkb" != "$exp_pk" || "$ctb" != "$exp_ct" || "$skb" != "$exp_sk" || "$ssb" != "$exp_ss" ]]; then
      printf 'Frost,%s,%s,%s,%s,,,,,%s,%s,%s,%s,%s,failed,size_mismatch\n' "$level" "$mode" "$backend" "$matrix_backend" "$pkb" "$ctb" "$skb" "$ssb" "$correct_iters" >> "$OUT_CSV"
      echo "[error] level=$level size mismatch api=($pkb,$ctb,$skb,$ssb) expected=($exp_pk,$exp_ct,$exp_sk,$exp_ss)"
      continue
    fi

    echo "[info] Running mode=$mode, level=$level, correctness=$correct_iters, bench_seconds=$bench_seconds, timeout=${timeout_s}s"
    tmp_log=$(mktemp)
    set +e
    timeout "$timeout_s" env PROFILE_U32="$PROFILE_U32" PROFILE_U32_AVX2="$PROFILE_U32" FROST_KEM_TEST_ITERATIONS="$correct_iters" FROST_KEM_BENCH_SECONDS="$bench_seconds" BENCH_VERBOSE="${BENCH_VERBOSE:-0}" DEBUG_BENCH="${DEBUG_BENCH:-0}" "$FROST_DIR/$bin" >"$tmp_log" 2>&1
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
      IFS=',' read -r kcyc ecyc dcyc tcyc iters <<< "$(parse_cycles "$tmp_log")"
      printf 'Frost,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,ok,%s\n' "$level" "$mode" "$backend" "$matrix_backend" "$kcyc" "$ecyc" "$dcyc" "$tcyc" "$pkb" "$ctb" "$skb" "$ssb" "${iters:-$correct_iters}" "$notes" >> "$OUT_CSV"
    elif [[ $rc -eq 124 ]]; then
      printf 'Frost,%s,%s,%s,%s,,,,,%s,%s,%s,%s,%s,timeout,%s\n' "$level" "$mode" "$backend" "$matrix_backend" "$pkb" "$ctb" "$skb" "$ssb" "$correct_iters" "$notes" >> "$OUT_CSV"
      echo "[warn] mode=$mode, level=$level timeout (${timeout_s}s)"
    else
      printf 'Frost,%s,%s,%s,%s,,,,,%s,%s,%s,%s,%s,failed,%s\n' "$level" "$mode" "$backend" "$matrix_backend" "$pkb" "$ctb" "$skb" "$ssb" "$correct_iters" "$notes" >> "$OUT_CSV"
      echo "[warn] mode=$mode, level=$level failed (exit=$rc)"
    fi

    if [[ "${BENCH_VERBOSE:-0}" == "1" || "${DEBUG_BENCH:-0}" == "1" ]]; then
      echo "[debug] ---- begin log mode=$mode level=$level ----"; cat "$tmp_log"; echo "[debug] ---- end log mode=$mode level=$level ----"
    fi
    rm -f "$tmp_log"
    done
  done
done

echo "[done] Benchmark complete. CSV written to $OUT_CSV"
