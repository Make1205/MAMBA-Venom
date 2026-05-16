#!/usr/bin/env bash
set -euo pipefail

OUT_CSV=${1:-/tmp/frost_profile_breakdown.csv}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FROST_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
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
MATRIX_A_BACKENDS=${MATRIX_A_BACKENDS:-${MATRIX_A_BACKEND:-AES128}}

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
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
RAW_CSV="$tmpdir/raw_components.csv"
printf 'scheme,level,mode,implementation_backend,matrix_backend,component,cycles,iterations,status,notes\n' > "$RAW_CSV"
read -r -a matrix_backends <<< "$MATRIX_A_BACKENDS"

for matrix_backend in "${matrix_backends[@]}"; do
  for mode in "${modes[@]}"; do
    echo "[profile] building matrix_backend=$matrix_backend mode=$mode with FROST_PROFILE_BREAKDOWN" >&2
    make -C "$FROST_DIR" clean >/dev/null
    if [[ "$mode" == "REFERENCE" ]]; then
      make -C "$FROST_DIR" OPT_LEVEL=REFERENCE MATRIX_A_BACKEND="$matrix_backend" \
        FROST_U16_STREAMING_MATMUL="$FROST_U16_STREAMING_MATMUL" \
        FROST_U16_MATERIALIZED_A_MATMUL="$FROST_U16_MATERIALIZED_A_MATMUL" \
        EXTRA_CFLAGS='-O3 -DFROST_PROFILE_BREAKDOWN' tests >/dev/null
    else
      make -C "$FROST_DIR" OPT_LEVEL=FAST MATRIX_A_BACKEND="$matrix_backend" \
        FROST_U16_STREAMING_MATMUL="$FROST_U16_STREAMING_MATMUL" \
        FROST_U16_MATERIALIZED_A_MATMUL="$FROST_U16_MATERIALIZED_A_MATMUL" \
        EXTRA_CFLAGS='-O3 -DFROST_PROFILE_BREAKDOWN' tests >/dev/null
    fi

    for level in "${levels[@]}"; do
    bin=$(level_bin "$level")
    backend=$(backend_tag "$mode" "$level")
    log="$tmpdir/${matrix_backend}_${mode}_${level}.log"
    echo "[profile] matrix_backend=$matrix_backend mode=$mode level=$level backend=$backend iterations=$FROST_PROFILE_ITERATIONS" >&2
    timeout "$PROFILE_TIMEOUT" env FROST_PROFILE_BREAKDOWN=1 PROFILE_ALL_LEVELS=1 \
      FROST_KEM_TEST_ITERATIONS="$FROST_PROFILE_ITERATIONS" \
      FROST_KEM_BENCH_SECONDS="$PROFILE_BENCH_SECONDS" \
      "$FROST_DIR/$bin" nobench >"$log" 2>&1

    python3 - "$log" Frost "$level" "$mode" "$backend" "$matrix_backend" >> "$RAW_CSV" <<'PY'
import csv
import re
import statistics
import sys
from collections import defaultdict

log_path, scheme, level, mode, backend, matrix_backend = sys.argv[1:]
values = defaultdict(list)
notes = {}

def to_int(kv, name):
    val = kv.get(name)
    if val is None or val == "":
        return None
    return int(val)

def add(component, value, note):
    if value is None:
        return
    values[component].append(value)
    notes.setdefault(component, note)

def add_sum(component, kv, names, note):
    parts = [to_int(kv, name) for name in names]
    if any(v is None for v in parts):
        return
    add(component, sum(parts), note)

for line in open(log_path, encoding="utf-8", errors="replace"):
    if not line.startswith("[profile-all]"):
        continue
    kv = dict(re.findall(r'([^\s=]+)=([^\s]+)', line))
    api = kv.get("api")
    if api == "keygen":
        add("KeyGen.KEM_Total_Profiled", to_int(kv, "total"), "profiling-build keygen total; not official full-KEM timing")
        add("KeyGen.Random", to_int(kv, "random"), "randombytes for keygen seeds")
        add("KeyGen.SeedExpand", to_int(kv, "seedexp"), "seed_A and S XOF expansion")
        add("KeyGen.Sample_S", to_int(kv, "cbd_s"), "CBD transform for S")
        add("KeyGen.Expand_A", to_int(kv, "genpublic_a_expand"), "keygen A expansion")
        add("KeyGen.A_times_S", to_int(kv, "genpublic_a_mul"), "keygen A*S multiplication")
        add("KeyGen.Dither_PK", to_int(kv, "d_pk_gen"), "keygen public-key dither")
        add("KeyGen.Quant_PK", to_int(kv, "quant_pk"), "keygen public-key quantization")
        add("KeyGen.Pack_PK", to_int(kv, "pack_pk"), "keygen public-key packing")
        add("KeyGen.PK_Hash", to_int(kv, "hash_aux"), "keygen h_pk")
    elif api == "encaps":
        add("Encaps.KEM_Total_Profiled", to_int(kv, "total"), "profiling-build encaps total; not official full-KEM timing")
        add("Encaps.PK_Hash", to_int(kv, "h_pk"), "encaps h_pk")
        add("Encaps.Sample_Message", to_int(kv, "message_sampling"), "randombytes for mu and salt")
        add("Encaps.FO_Hash", to_int(kv, "g_hash"), "G hash h_pk||mu||salt")
        add("Encaps.SeedExpand_R", to_int(kv, "sigma_to_r_xof"), "R XOF expansion")
        add("Encaps.Sample_R", to_int(kv, "r_sampling"), "CBD transform for R")
        add("Encaps.Expand_A", to_int(kv, "genpublic_a_expand"), "encaps A expansion for A^T*R")
        add("Encaps.AT_times_R", to_int(kv, "genpublic_a_mul"), "encaps A^T*R multiplication")
        add("Encaps.Dither_U", to_int(kv, "gen_dither_du"), "encaps U dither")
        add("Encaps.Quant_U", to_int(kv, "quant_u"), "encaps U quantization")
        add("Encaps.Unpack_PK", to_int(kv, "unpack_pk"), "encaps public-key unpack")
        add("Encaps.Dither_PK", to_int(kv, "d_pk_gen"), "encaps public-key dither for reconstruction")
        add("Encaps.Recon_PK", to_int(kv, "bhat_reconstruct"), "encaps public-key reconstruction")
        add("Encaps.BhatT_times_R", to_int(kv, "mul_btr"), "encaps B^T*R multiplication")
        add("Encaps.Encode_Message", to_int(kv, "encode_msg"), "encaps message encoding and add")
        add("Encaps.Dither_V", to_int(kv, "gen_dither_dv"), "encaps V dither")
        add("Encaps.Quant_V", to_int(kv, "quant_v"), "encaps V quantization")
        add("Encaps.Pack_CT", to_int(kv, "pack_ct"), "encaps ciphertext packing")
        add("Encaps.KDF", to_int(kv, "final_hash"), "encaps final shared-secret hash")
    elif api == "decaps":
        add("Decaps.KEM_Total_Profiled", to_int(kv, "total"), "profiling-build decaps total; not official full-KEM timing")
        add("Decaps.Unpack_CT", to_int(kv, "unpack_ct"), "decaps ciphertext unpack")
        add("Decaps.Dither_U", to_int(kv, "gen_dither_du"), "decaps U dither for reconstruction")
        add("Decaps.Dither_V", to_int(kv, "gen_dither_dv"), "decaps V dither for reconstruction")
        add("Decaps.Recon_U", to_int(kv, "reconstruct_u"), "decaps U reconstruction")
        add("Decaps.Recon_V", to_int(kv, "reconstruct_v"), "decaps V reconstruction")
        add("Decaps.ST_times_U", to_int(kv, "mul_stu"), "decaps S^T*U multiplication")
        add("Decaps.Decode_Message", to_int(kv, "msg_decode"), "decaps message decode")
        add("Decaps.Sample_S", to_int(kv, "sk_s_sampling"), "decaps regenerate S from sk seed")
        add("Decaps.FO_Hash", to_int(kv, "g_hash"), "decaps G hash h_pk||muprime||salt")
        add("Decaps.SeedExpand_R", to_int(kv, "sigma_to_r_xof"), "decaps reenc R XOF expansion")
        add("Decaps.Sample_R", to_int(kv, "r_sampling"), "decaps reenc R CBD transform")
        add("Decaps.ReEnc_Expand_A", to_int(kv, "reenc_a_expand"), "decaps re-encryption A expansion")
        add("Decaps.ReEnc_AT_times_R", to_int(kv, "reenc_a_mul"), "decaps re-encryption A^T*R multiplication")
        add("Decaps.ReEnc_Unpack_PK", to_int(kv, "reenc_unpack_pk"), "decaps re-encryption public-key unpack")
        add("Decaps.ReEnc_Dither_PK", to_int(kv, "reenc_d_pk"), "decaps re-encryption public-key dither")
        add("Decaps.ReEnc_Recon_PK", to_int(kv, "reenc_bhat_reconstruct"), "decaps re-encryption public-key reconstruction")
        add("Decaps.ReEnc_BhatT_times_R", to_int(kv, "reenc_btr"), "decaps re-encryption B^T*R multiplication")
        add("Decaps.ReEnc_Dither_U", to_int(kv, "reenc_du"), "decaps re-encryption U dither")
        add("Decaps.ReEnc_Dither_V", to_int(kv, "reenc_dv"), "decaps re-encryption V dither")
        add("Decaps.ReEnc_Quant_U", to_int(kv, "reenc_quant_u"), "decaps re-encryption U quantization")
        add("Decaps.ReEnc_Quant_V", to_int(kv, "reenc_quant_v"), "decaps re-encryption V quantization and message add")
        add("Decaps.CT_Compare", to_int(kv, "ct_compare"), "decaps ciphertext comparison and key select")
        add("Decaps.KDF", to_int(kv, "final_hash"), "decaps final shared-secret hash")

writer = csv.writer(sys.stdout, lineterminator="\n")
for component in sorted(values):
    vals = values[component]
    median = int(round(statistics.median(vals)))
    writer.writerow([scheme, level, mode, backend, matrix_backend, component, median, len(vals), "ok", notes.get(component, "")])
PY
    done
  done
done

cp "$RAW_CSV" "$CANONICAL_RAW"
python3 "${SCRIPT_DIR}/summarize_profile_breakdown.py" "$CANONICAL_RAW" "$OUT_CSV" "$TABLE_TEX"
if [[ "$SUMMARY_CSV" != "$OUT_CSV" ]]; then
  cp "$OUT_CSV" "$SUMMARY_CSV"
fi
echo "[profile] wrote summary CSV: $OUT_CSV" >&2
echo "[profile] updated canonical raw CSV: $CANONICAL_RAW" >&2
echo "[profile] updated canonical summary CSV: $SUMMARY_CSV" >&2
echo "[profile] wrote LaTeX table: $TABLE_TEX" >&2
