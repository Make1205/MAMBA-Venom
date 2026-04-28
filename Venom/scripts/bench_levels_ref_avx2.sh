#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VENOM_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
OUT_CSV=${1:-"${VENOM_DIR}/bench_results_$(date -u +%Y%m%dT%H%M%SZ).csv"}

ALL_MODES=(REFERENCE AVX2)
ALL_LEVELS=(128 192 256 384 512)
ONLY_MODE=${ONLY_MODE:-}
ONLY_LEVEL=${ONLY_LEVEL:-}
REPS=${REPS:-}

get_level_env_default(){ local p="$1" l="$2" d="$3" ar="${4:-0}"; local v="${p}_${l}"; local val="${!v:-}"; if [[ "$ar" == "1" && -n "$REPS" ]]; then echo "$REPS"; elif [[ -n "$val" ]]; then echo "$val"; else echo "$d"; fi; }
api_header_for_level(){ case "$1" in 128) echo api_venom128.h;;192) echo api_venom192.h;;256) echo api_venom256.h;;384) echo api_venom384.h;;512) echo api_venom512.h;; esac; }
level_bin(){ case "$1" in 128) echo venom128/test_KEM;;192) echo venom192/test_KEM;;256) echo venom256/test_KEM;;384) echo venom384/test_KEM;;512) echo venom512/test_KEM;; esac; }

get_bench_seconds(){ case "$1" in 128|192|256) get_level_env_default VENOM_BENCH_REPS "$1" 1 1;;384) get_level_env_default VENOM_BENCH_REPS "$1" 3 1;;512) get_level_env_default VENOM_BENCH_REPS "$1" 1 1;; esac; }
get_correct_iters(){ case "$1" in 128|192|256) get_level_env_default VENOM_KAT_REPS "$1" 1000 1;;384) get_level_env_default VENOM_KAT_REPS "$1" 20 1;;512) get_level_env_default VENOM_KAT_REPS "$1" 10 1;; esac; }
get_timeout_secs(){ case "$1" in 128|192|256) get_level_env_default VENOM_TIMEOUT "$1" 120;;384) get_level_env_default VENOM_TIMEOUT "$1" 600;;512) get_level_env_default VENOM_TIMEOUT "$1" 1200;; esac; }

level_params(){ case "$1" in
128) echo "q=32768,qbits=15,n=640,m=640,ell=8,eta_s=2,eta_r=2,b_msg=2,t_pk=11,t_u=10,t_v=6";;
192) echo "q=32768,qbits=15,n=976,m=976,ell=8,eta_s=2,eta_r=2,b_msg=3,t_pk=12,t_u=12,t_v=6";;
256) echo "q=65536,qbits=16,n=1344,m=1344,ell=8,eta_s=2,eta_r=2,b_msg=4,t_pk=13,t_u=13,t_v=8";;
384) echo "q=262144,qbits=18,n=2176,m=2176,ell=8,eta_s=3,eta_r=3,b_msg=6,t_pk=16,t_u=15,t_v=13";;
512) echo "q=1048576,qbits=20,n=3072,m=3072,ell=8,eta_s=4,eta_r=4,b_msg=8,t_pk=18,t_u=18,t_v=11";;
esac; }
expected_sizes(){ case "$1" in 128) echo "7072,6480,9056,16";;192) echo "11744,11792,14736,24";;256) echo "17504,17568,21600,32";;384) echo "34848,32776,41440,48";;512) echo "55328,55416,67680,64";; esac; }
query_sizes_from_api(){ local h; h="$(api_header_for_level "$1")"; cpp -dM -include "$VENOM_DIR/src/$h" /dev/null | awk '$2=="CRYPTO_PUBLICKEYBYTES"{pk=$3}$2=="CRYPTO_CIPHERTEXTBYTES"{ct=$3}$2=="CRYPTO_SECRETKEYBYTES"{sk=$3}$2=="CRYPTO_BYTES"{ss=$3}END{printf "%s,%s,%s,%s\n",pk,ct,sk,ss}'; }

parse_cycles(){ awk '$1=="Key"&&$2=="generation"{ki=$3;k=(NF>=7?$(NF-1):"")}$1=="KEM"&&$2=="encapsulate"{ei=$3;e=(NF>=7?$(NF-1):"")}$1=="KEM"&&$2=="decapsulate"{di=$3;d=(NF>=7?$(NF-1):"")}END{tot="";if(k!=""&&e!=""&&d!="")tot=k+e+d;it=ki;if(ei>it)it=ei;if(di>it)it=di;printf "%s,%s,%s,%s,%s\n",k,e,d,tot,it}' "$1"; }

printf 'scheme,level,mode,backend,keygen_cycles,encaps_cycles,decaps_cycles,total_cycles,pk_bytes,ct_bytes,sk_bytes,ss_bytes,iterations,status,notes\n' > "$OUT_CSV"
echo "[info] Output CSV: $OUT_CSV"
echo "[info] Running benchmarks for OPT_LEVEL=REFERENCE and AVX2."
echo "[info] FORCE_L256_AVX2=${FORCE_L256_AVX2:-0}: using default stable code path for Level-192/256."

modes=("${ALL_MODES[@]}"); levels=("${ALL_LEVELS[@]}")
[[ -n "$ONLY_MODE" ]] && modes=("$ONLY_MODE")
[[ -n "$ONLY_LEVEL" ]] && levels=("$ONLY_LEVEL")

for mode in "${modes[@]}"; do
  echo "[info] ===== Building mode: $mode ====="
  make -C "$VENOM_DIR" clean >/dev/null
  if [[ "$mode" == "REFERENCE" ]]; then make -C "$VENOM_DIR" OPT_LEVEL=REFERENCE tests >/dev/null; else
    if [[ "${FORCE_L256_AVX2:-0}" == "1" ]]; then make -C "$VENOM_DIR" OPT_LEVEL=FAST EXTRA_CFLAGS="-O3 -DFORCE_USE_AVX2_FOR_L256" tests >/dev/null; else make -C "$VENOM_DIR" OPT_LEVEL=FAST tests >/dev/null; fi
  fi

  for level in "${levels[@]}"; do
    bin=$(level_bin "$level"); timeout_s=$(get_timeout_secs "$level"); correct_iters=$(get_correct_iters "$level"); bench_seconds=$(get_bench_seconds "$level")
    backend="ref"; notes=""
    [[ "$level" == "384" || "$level" == "512" ]] && backend="ref_u32"
    if [[ "$mode" == "AVX2" ]]; then
      backend="avx2"
      if [[ "$level" == "384" || "$level" == "512" ]]; then
        if [[ "${FORCE_U32_REF:-0}" == "1" ]]; then
          backend="avx2_fallback_ref_u32"; notes="avx2_fallback_ref_u32"
          echo "[info] Venom-${level} AVX2 path: forced fallback to ref-u32 (FORCE_U32_REF=1)"
        else
          backend="avx2_u32_full"; notes="avx2_u32_full"
          echo "[info] Venom-${level} AVX2 path: u32 AVX2 backend enabled"
        fi
      fi
    fi

    echo "[param-check] level=$level $(level_params "$level")"
    IFS=',' read -r pkb ctb skb ssb <<< "$(query_sizes_from_api "$level")"
    IFS=',' read -r exp_pk exp_ct exp_sk exp_ss <<< "$(expected_sizes "$level")"
    echo "[param-check] level=$level pk_bytes=$pkb ct_bytes=$ctb sk_bytes=$skb ss_bytes=$ssb"
    if [[ "$pkb" != "$exp_pk" || "$ctb" != "$exp_ct" || "$skb" != "$exp_sk" || "$ssb" != "$exp_ss" ]]; then
      printf 'Venom,%s,%s,%s,,,,,%s,%s,%s,%s,%s,failed,size_mismatch\n' "$level" "$mode" "$backend" "$pkb" "$ctb" "$skb" "$ssb" "$correct_iters" >> "$OUT_CSV"
      echo "[error] level=$level size mismatch api=($pkb,$ctb,$skb,$ssb) expected=($exp_pk,$exp_ct,$exp_sk,$exp_ss)"
      continue
    fi

    echo "[info] Running mode=$mode, level=$level, correctness=$correct_iters, bench_seconds=$bench_seconds, timeout=${timeout_s}s"
    tmp_log=$(mktemp)
    set +e
    timeout "$timeout_s" env VENOM_KEM_TEST_ITERATIONS="$correct_iters" VENOM_KEM_BENCH_SECONDS="$bench_seconds" BENCH_VERBOSE="${BENCH_VERBOSE:-0}" DEBUG_BENCH="${DEBUG_BENCH:-0}" "$VENOM_DIR/$bin" >"$tmp_log" 2>&1
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
      IFS=',' read -r kcyc ecyc dcyc tcyc iters <<< "$(parse_cycles "$tmp_log")"
      printf 'Venom,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,ok,%s\n' "$level" "$mode" "$backend" "$kcyc" "$ecyc" "$dcyc" "$tcyc" "$pkb" "$ctb" "$skb" "$ssb" "${iters:-$correct_iters}" "$notes" >> "$OUT_CSV"
    elif [[ $rc -eq 124 ]]; then
      printf 'Venom,%s,%s,%s,,,,,%s,%s,%s,%s,%s,timeout,%s\n' "$level" "$mode" "$backend" "$pkb" "$ctb" "$skb" "$ssb" "$correct_iters" "$notes" >> "$OUT_CSV"
      echo "[warn] mode=$mode, level=$level timeout (${timeout_s}s)"
    else
      printf 'Venom,%s,%s,%s,,,,,%s,%s,%s,%s,%s,failed,%s\n' "$level" "$mode" "$backend" "$pkb" "$ctb" "$skb" "$ssb" "$correct_iters" "$notes" >> "$OUT_CSV"
      echo "[warn] mode=$mode, level=$level failed (exit=$rc)"
    fi

    if [[ "${BENCH_VERBOSE:-0}" == "1" || "${DEBUG_BENCH:-0}" == "1" ]]; then
      echo "[debug] ---- begin log mode=$mode level=$level ----"; cat "$tmp_log"; echo "[debug] ---- end log mode=$mode level=$level ----"
    fi
    rm -f "$tmp_log"
  done
done

echo "[done] Benchmark complete. CSV written to $OUT_CSV"
