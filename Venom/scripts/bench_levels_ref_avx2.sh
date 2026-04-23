#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VENOM_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)

OUT_CSV=${1:-"${VENOM_DIR}/bench_results_$(date -u +%Y%m%dT%H%M%SZ).csv"}
MODES=(REFERENCE FAST)
LEVELS=(640 976 1344)

printf 'mode,level,operation,iterations,total_time_s,time_mean_us,time_stdev_us,cycles_mean,cycles_stdev\n' > "${OUT_CSV}"

echo "[info] Output CSV: ${OUT_CSV}"
echo "[info] Running benchmarks for OPT_LEVEL=REFERENCE and OPT_LEVEL=FAST (AVX2-capable build)."
echo "[info] Note: in current code, Level-3/5 may disable USE_AVX2 specialization inside source for stability."

parse_and_append() {
    local mode="$1"
    local level="$2"
    local input_file="$3"

    awk -v mode="${mode}" -v level="${level}" '
        function emit(op, start_idx) {
            n = NF - start_idx + 1;
            iterations = $(start_idx + 0);
            total_s    = $(start_idx + 1);
            mean_us    = $(start_idx + 2);
            stdev_us   = $(start_idx + 3);

            if (n >= 6) {
                cyc_mean  = $(start_idx + 4);
                cyc_stdev = $(start_idx + 5);
            } else {
                cyc_mean  = "";
                cyc_stdev = "";
            }

            printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n", mode, level, op, iterations, total_s, mean_us, stdev_us, cyc_mean, cyc_stdev;
        }

        $1 == "Key" && $2 == "generation"  { emit("Key generation", 3) }
        $1 == "KEM" && $2 == "encapsulate" { emit("KEM encapsulate", 3) }
        $1 == "KEM" && $2 == "decapsulate" { emit("KEM decapsulate", 3) }
    ' "${input_file}" >> "${OUT_CSV}"
}

for mode in "${MODES[@]}"; do
    echo "[info] ===== Building mode: ${mode} ====="
    make -C "${VENOM_DIR}" clean >/dev/null
    make -C "${VENOM_DIR}" OPT_LEVEL="${mode}" tests >/dev/null

    for level in "${LEVELS[@]}"; do
        case "${level}" in
            640) bin="venom1/test_KEM" ;;
            976) bin="venom3/test_KEM" ;;
            1344) bin="venom5/test_KEM" ;;
            *) echo "[error] Unknown level: ${level}" >&2; exit 1 ;;
        esac

        echo "[info] Running mode=${mode}, level=${level}"
        tmp_log=$(mktemp)
        "${VENOM_DIR}/${bin}" > "${tmp_log}"
        parse_and_append "${mode}" "${level}" "${tmp_log}"
        rm -f "${tmp_log}"
    done
done

echo "[done] Benchmark complete. CSV written to ${OUT_CSV}"
