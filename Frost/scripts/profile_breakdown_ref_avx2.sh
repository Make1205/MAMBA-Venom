#!/usr/bin/env bash
set -euo pipefail

OUT_CSV=${1:-/tmp/frost_profile_breakdown.csv}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FROST_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
REPO_ROOT=$(cd -- "${FROST_DIR}/.." && pwd)
SUMMARY_CSV=${FROST_PROFILE_SUMMARY_CSV:-"${FROST_DIR}/benchmarks/breakdown_summary.csv"}
TABLE_TEX=${FROST_PROFILE_TABLE_TEX:-"${FROST_DIR}/benchmarks/breakdown_table.tex"}
CANONICAL_RAW=${FROST_PROFILE_CANONICAL_RAW:-"${FROST_DIR}/benchmarks/breakdown_profile.csv"}

ONLY_LEVEL=${ONLY_LEVEL:-}
ONLY_MODE=${ONLY_MODE:-}
RUN_REFERENCE=${RUN_REFERENCE:-1}
RUN_AVX2=${RUN_AVX2:-1}
FROST_U16_STREAMING_MATMUL=${FROST_U16_STREAMING_MATMUL:-0}
FROST_U16_MATERIALIZED_A_MATMUL=${FROST_U16_MATERIALIZED_A_MATMUL:-0}
PROFILE_LEVELS=${PROFILE_LEVELS:-128 192 256}
FROST_PROFILE_ITERATIONS=${FROST_PROFILE_ITERATIONS:-${PROFILE_ITERS:-10}}
PROFILE_BENCH_SECONDS=${PROFILE_BENCH_SECONDS:-0}
PROFILE_TIMEOUT=${PROFILE_TIMEOUT:-600}

level_bin(){ case "$1" in 128) echo frost128/test_KEM;;192) echo frost192/test_KEM;;256) echo frost256/test_KEM;;*) return 1;; esac; }
backend_tag(){
  local mode="$1" level="$2"
  if [[ "$mode" == "REFERENCE" ]]; then
    echo ref
  elif [[ "$level" == "128" || "$level" == "192" || "$level" == "256" ]]; then
    echo avx2_u16
  else
    echo unknown
  fi
}

modes=()
if [[ -n "$ONLY_MODE" ]]; then
  modes=("$([[ "$ONLY_MODE" == "AVX2" ]] && echo FAST || echo "$ONLY_MODE")")
else
  [[ "$RUN_REFERENCE" == "1" ]] && modes+=("REFERENCE")
  [[ "$RUN_AVX2" == "1" ]] && modes+=("FAST")
fi
if [[ ${#modes[@]} -eq 0 ]]; then
  echo "[error] no profiling mode enabled" >&2
  exit 1
fi
read -r -a levels <<< "$PROFILE_LEVELS"
[[ -n "$ONLY_LEVEL" ]] && levels=("$ONLY_LEVEL")

mkdir -p "$(dirname -- "$OUT_CSV")" "${FROST_DIR}/benchmarks"
printf 'scheme,level,mode,backend,component,cycles,iterations,status,notes\n' > "$OUT_CSV"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

for mode in "${modes[@]}"; do
  echo "[profile] building mode=$mode with FROST_PROFILE_BREAKDOWN" >&2
  make -C "$FROST_DIR" clean >/dev/null
  if [[ "$mode" == "REFERENCE" ]]; then
    make -C "$FROST_DIR" OPT_LEVEL=REFERENCE \
      FROST_U16_STREAMING_MATMUL="$FROST_U16_STREAMING_MATMUL" \
      FROST_U16_MATERIALIZED_A_MATMUL="$FROST_U16_MATERIALIZED_A_MATMUL" \
      EXTRA_CFLAGS='-O3 -DFROST_PROFILE_BREAKDOWN' tests >/dev/null
  else
    make -C "$FROST_DIR" OPT_LEVEL=FAST \
      FROST_U16_STREAMING_MATMUL="$FROST_U16_STREAMING_MATMUL" \
      FROST_U16_MATERIALIZED_A_MATMUL="$FROST_U16_MATERIALIZED_A_MATMUL" \
      EXTRA_CFLAGS='-O3 -DFROST_PROFILE_BREAKDOWN' tests >/dev/null
  fi

  for level in "${levels[@]}"; do
    bin=$(level_bin "$level")
    backend=$(backend_tag "$mode" "$level")
    log="$tmpdir/${mode}_${level}.log"
    echo "[profile] mode=$mode level=$level backend=$backend iterations=$FROST_PROFILE_ITERATIONS" >&2
    timeout "$PROFILE_TIMEOUT" env FROST_PROFILE_BREAKDOWN=1 PROFILE_ALL_LEVELS=1 \
      FROST_KEM_TEST_ITERATIONS="$FROST_PROFILE_ITERATIONS" \
      FROST_KEM_BENCH_SECONDS="$PROFILE_BENCH_SECONDS" \
      "$FROST_DIR/$bin" nobench >"$log" 2>&1

    awk -v scheme=Frost -v level="$level" -v mode="$mode" -v backend="$backend" '
      function add(comp, val, note, key) {
        if (val == "" || val == "NA") return;
        key=comp SUBSEP note;
        sums[key] += val + 0;
        counts[key]++;
      }
      /^\[profile-all\]/ {
        delete kv;
        for (i=1; i<=NF; i++) {
          split($i, a, "=");
          if (length(a[1]) > 0 && length(a[2]) > 0) kv[a[1]]=a[2];
        }
        api=kv["api"];
        if (api == "keygen") {
          add("KEM_KeyGen", kv["total"], "api=keygen total");
          add("PKE_KeyGen", kv["seedexp"]+kv["cbd_s"]+kv["mul_as"]+kv["d_pk_gen"]+kv["quant_pk"]+kv["pack_pk"], "keygen core excluding random/pk hash/other");
          add("RandomSeed", kv["random"], "randombytes for keygen seeds");
          add("SeedExpand_S", kv["seedexp"], "seed_A and S XOF expansion");
          add("Sample_S", kv["cbd_s"], "CBD transform for S");
          add("Expand_A", kv["genpublic_a_expand"], "keygen A expansion");
          add("A_times_S", kv["genpublic_a_mul"], "keygen A*S multiplication");
          add("Dither_PK", kv["d_pk_gen"], "keygen public-key dither");
          add("Quant_PK", kv["quant_pk"], "keygen public-key quantization");
          add("Pack_PK", kv["pack_pk"], "keygen public-key packing");
          add("PK_Hash", kv["hash_aux"], "keygen h_pk");
        } else if (api == "encaps") {
          add("KEM_Encaps", kv["total"], "api=encaps total");
          add("PKE_Enc", kv["sigma_to_r_xof"]+kv["r_sampling"]+kv["mul_atr"]+kv["gen_dither_du"]+kv["quant_u"]+kv["unpack_pk"]+kv["d_pk_gen"]+kv["bhat_reconstruct"]+kv["mul_btr"]+kv["encode_msg"]+kv["gen_dither_dv"]+kv["quant_v"]+kv["pack_ct"], "encapsulation PKE core excluding random/FO/KDF/other");
          add("RandomSeed", kv["message_sampling"], "randombytes for mu and salt");
          add("PK_Hash", kv["h_pk"], "encaps h_pk");
          add("FO_Hash", kv["g_hash"], "G hash h_pk||mu||salt");
          add("SeedExpand_R", kv["sigma_to_r_xof"], "R XOF expansion");
          add("Sample_R", kv["r_sampling"], "CBD transform for R");
          add("Expand_A", kv["genpublic_a_expand"], "encaps A expansion for A^T*R");
          add("AT_times_R", kv["genpublic_a_mul"], "encaps A^T*R multiplication");
          add("Dither_U", kv["gen_dither_du"], "encaps U dither");
          add("Quant_U", kv["quant_u"], "encaps U quantization");
          add("Unpack_PK", kv["unpack_pk"], "encaps public-key unpack");
          add("Dither_PK", kv["d_pk_gen"], "encaps public-key dither for reconstruction");
          add("Recon_PK", kv["bhat_reconstruct"], "encaps public-key reconstruction");
          add("BhatT_times_R", kv["mul_btr"], "encaps B^T*R multiplication");
          add("Dither_V", kv["gen_dither_dv"], "encaps V dither");
          add("Quant_V", kv["quant_v"], "encaps V quantization");
          add("Pack_CT", kv["pack_ct"], "encaps ciphertext packing");
          add("KDF", kv["final_hash"], "encaps final shared-secret hash");
        } else if (api == "decaps") {
          add("KEM_Decaps", kv["total"], "api=decaps total");
          add("PKE_Dec", kv["unpack_ct"]+kv["gen_dither_du"]+kv["gen_dither_dv"]+kv["reconstruct_u"]+kv["reconstruct_v"]+kv["mul_stu"]+kv["msg_decode"], "decapsulation PKE decrypt core");
          add("Unpack_CT", kv["unpack_ct"], "decaps ciphertext unpack");
          add("Dither_U", kv["gen_dither_du"]+kv["reenc_du"], "decaps U dither plus reenc U dither");
          add("Dither_V", kv["gen_dither_dv"]+kv["reenc_dv"], "decaps V dither plus reenc V dither");
          add("Recon_U", kv["reconstruct_u"], "decaps U reconstruction");
          add("Recon_V", kv["reconstruct_v"], "decaps V reconstruction");
          add("ST_times_U", kv["mul_stu"], "decaps S^T*U multiplication");
          add("Sample_S", kv["sk_s_sampling"], "decaps regenerate S from sk seed");
          add("FO_Hash", kv["g_hash"], "decaps G hash h_pk||muprime||salt");
          add("SeedExpand_R", kv["sigma_to_r_xof"], "decaps reenc R XOF expansion");
          add("Sample_R", kv["r_sampling"], "decaps reenc R CBD transform");
          add("Expand_A", kv["reenc_a_expand"], "decaps reenc A expansion");
          add("AT_times_R", kv["reenc_a_mul"], "decaps reenc A^T*R multiplication");
          add("Unpack_PK", kv["reenc_unpack_pk"], "decaps reenc public-key unpack");
          add("Dither_PK", kv["reenc_d_pk"], "decaps reenc public-key dither");
          add("Recon_PK", kv["reenc_bhat_reconstruct"], "decaps reenc public-key reconstruction");
          add("BhatT_times_R", kv["reenc_btr"], "decaps reenc B^T*R multiplication");
          add("Quant_U", kv["reenc_quant_u"], "decaps reenc U quantization");
          add("Quant_V", kv["reenc_quant_v"], "decaps reenc V quantization and message add");
          add("KDF", kv["final_hash"], "decaps final shared-secret hash");
        }
      }
      END {
        for (key in sums) {
          split(key, parts, SUBSEP);
          printf "%s,%s,%s,%s,%s,%.0f,%d,ok,%s\n", scheme, level, mode, backend, parts[1], sums[key]/counts[key], counts[key], parts[2];
        }
      }
    ' "$log" | sort -t, -k5,5 >> "$OUT_CSV"
  done
done

cp "$OUT_CSV" "$CANONICAL_RAW"
python3 "${SCRIPT_DIR}/summarize_profile_breakdown.py" "$CANONICAL_RAW" "$SUMMARY_CSV" "$TABLE_TEX"
echo "[profile] wrote raw CSV: $OUT_CSV" >&2
echo "[profile] updated canonical raw CSV: $CANONICAL_RAW" >&2
echo "[profile] wrote summary CSV: $SUMMARY_CSV" >&2
echo "[profile] wrote LaTeX table: $TABLE_TEX" >&2
