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

get_level_env_default() {
    local prefix="$1" level="$2" default="$3"
    local allow_reps="${4:-0}"
    local var="${prefix}_${level}"
    local val="${!var:-}"
    if [[ "$allow_reps" == "1" && -n "$REPS" ]]; then
        echo "$REPS"
    elif [[ -n "$val" ]]; then
        echo "$val"
    else
        echo "$default"
    fi
}

get_bench_seconds() {
    local level="$1"
    case "$level" in
        128|192|256) get_level_env_default VENOM_BENCH_REPS "$level" 1 1 ;;
        384) get_level_env_default VENOM_BENCH_REPS "$level" 3 1 ;;
        512) get_level_env_default VENOM_BENCH_REPS "$level" 1 1 ;;
    esac
}

get_correct_iters() {
    local level="$1"
    case "$level" in
        128|192|256) get_level_env_default VENOM_KAT_REPS "$level" 100 1 ;;
        384) get_level_env_default VENOM_KAT_REPS "$level" 20 1 ;;
        512) get_level_env_default VENOM_KAT_REPS "$level" 10 1 ;;
    esac
}

get_timeout_secs() {
    local level="$1"
    case "$level" in
        128|192|256) get_level_env_default VENOM_TIMEOUT "$level" 120 ;;
        384) get_level_env_default VENOM_TIMEOUT "$level" 600 ;;
        512) get_level_env_default VENOM_TIMEOUT "$level" 1200 ;;
    esac
}

level_bin() {
    case "$1" in
        128) echo "venom128/test_KEM" ;;
        192) echo "venom192/test_KEM" ;;
        256) echo "venom256/test_KEM" ;;
        384) echo "venom384/test_KEM" ;;
        512) echo "venom512/test_KEM" ;;
        *) return 1 ;;
    esac
}

level_sizes() {
    case "$1" in
        128) echo "6432,5824,16704,16" ;;
        192) echo "9792,9816,25456,24" ;;
        256) echo "13472,13504,35040,32" ;;
        384) echo "34848,32776,41440,48" ;;
        512) echo "55328,55416,67680,64" ;;
    esac
}

parse_cycles() {
    local file="$1"
    awk '
        $1 == "Key" && $2 == "generation"  { ki=$3; k=(NF>=7?$(NF-1):"") }
        $1 == "KEM" && $2 == "encapsulate" { ei=$3; e=(NF>=7?$(NF-1):"") }
        $1 == "KEM" && $2 == "decapsulate" { di=$3; d=(NF>=7?$(NF-1):"") }
        END {
            if (k == "") k = "";
            if (e == "") e = "";
            if (d == "") d = "";
            tot = "";
            if (k != "" && e != "" && d != "") tot = k + e + d;
            it = ki; if (ei > it) it = ei; if (di > it) it = di;
            printf "%s,%s,%s,%s,%s\n", k, e, d, tot, it;
        }
    ' "$file"
}

printf 'scheme,level,mode,backend,keygen_cycles,encaps_cycles,decaps_cycles,total_cycles,pk_bytes,ct_bytes,sk_bytes,ss_bytes,iterations,status,notes\n' > "$OUT_CSV"

echo "[info] Output CSV: ${OUT_CSV}"
echo "[info] Running benchmarks for OPT_LEVEL=REFERENCE and AVX2."
echo "[info] FORCE_L256_AVX2=${FORCE_L256_AVX2:-0}: using default stable code path for Level-192/256."

modes=("${ALL_MODES[@]}")
levels=("${ALL_LEVELS[@]}")
if [[ -n "$ONLY_MODE" ]]; then modes=("$ONLY_MODE"); fi
if [[ -n "$ONLY_LEVEL" ]]; then levels=("$ONLY_LEVEL"); fi

for mode in "${modes[@]}"; do
    echo "[info] ===== Building mode: ${mode} ====="
    make -C "$VENOM_DIR" clean >/dev/null
    if [[ "$mode" == "REFERENCE" ]]; then
        make -C "$VENOM_DIR" OPT_LEVEL=REFERENCE tests >/dev/null
    else
        if [[ "${FORCE_L256_AVX2:-0}" == "1" ]]; then
            make -C "$VENOM_DIR" OPT_LEVEL=FAST EXTRA_CFLAGS="-O3 -DFORCE_USE_AVX2_FOR_L256" tests >/dev/null
        else
            make -C "$VENOM_DIR" OPT_LEVEL=FAST tests >/dev/null
        fi
    fi

    for level in "${levels[@]}"; do
        bin=$(level_bin "$level")
        timeout_s=$(get_timeout_secs "$level")
        correct_iters=$(get_correct_iters "$level")
        bench_seconds=$(get_bench_seconds "$level")
        backend="ref"
        notes=""

        if [[ "$mode" == "AVX2" ]]; then
            backend="avx2"
            if [[ "$level" == "384" || "$level" == "512" ]]; then
                backend="ref-u32"
                notes="avx2_fallback_ref_u32"
                echo "[info] Venom-${level} AVX2 path: fallback to ref-u32"
            fi
        fi

        echo "[info] Running mode=${mode}, level=${level}, correctness=${correct_iters}, bench_seconds=${bench_seconds}, timeout=${timeout_s}s"

        tmp_log=$(mktemp)
        set +e
        timeout "$timeout_s" env \
            VENOM_KEM_TEST_ITERATIONS="$correct_iters" \
            VENOM_KEM_BENCH_SECONDS="$bench_seconds" \
            BENCH_VERBOSE="${BENCH_VERBOSE:-0}" \
            DEBUG_BENCH="${DEBUG_BENCH:-0}" \
            "$VENOM_DIR/$bin" >"$tmp_log" 2>&1
        rc=$?
        set -e

        IFS=',' read -r pkb ctb skb ssb <<< "$(level_sizes "$level")"

        if [[ $rc -eq 0 ]]; then
            IFS=',' read -r kcyc ecyc dcyc tcyc iters <<< "$(parse_cycles "$tmp_log")"
            printf "Venom,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,ok,%s\n" \
                "$level" "$mode" "$backend" "$kcyc" "$ecyc" "$dcyc" "$tcyc" \
                "$pkb" "$ctb" "$skb" "$ssb" "${iters:-$correct_iters}" "$notes" >> "$OUT_CSV"
        elif [[ $rc -eq 124 ]]; then
            printf "Venom,%s,%s,%s,,,,,%s,%s,%s,%s,%s,timeout,%s\n" \
                "$level" "$mode" "$backend" "$pkb" "$ctb" "$skb" "$ssb" "$correct_iters" "$notes" >> "$OUT_CSV"
            echo "[warn] mode=${mode}, level=${level} timeout (${timeout_s}s)"
        else
            printf "Venom,%s,%s,%s,,,,,%s,%s,%s,%s,%s,failed,%s\n" \
                "$level" "$mode" "$backend" "$pkb" "$ctb" "$skb" "$ssb" "$correct_iters" "$notes" >> "$OUT_CSV"
            echo "[warn] mode=${mode}, level=${level} failed (exit=${rc})."
        fi

        if [[ "${BENCH_VERBOSE:-0}" == "1" || "${DEBUG_BENCH:-0}" == "1" ]]; then
            echo "[debug] ---- begin log mode=${mode} level=${level} ----"
            cat "$tmp_log"
            echo "[debug] ---- end log mode=${mode} level=${level} ----"
        fi
        rm -f "$tmp_log"
    done
done

echo "[done] Benchmark complete. CSV written to ${OUT_CSV}"
