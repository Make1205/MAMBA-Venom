#!/usr/bin/env bash
set -euo pipefail
CSV_PATH=${1:?"usage: $0 <bench.csv>"}
awk -F',' '
NR==1 { next }
$14=="ok" {
  level=$2; mode=$3; total=$8+0
  if (mode=="REFERENCE") ref[level]=total
  else if (mode=="AVX2") avx[level]=total
}
END {
  printf "level,ref_total,avx2_total,speedup(ref/avx2)\n"
  for (lvl in ref) {
    if (lvl in avx && avx[lvl] > 0) {
      printf "%s,%.0f,%.0f,%.3f\n", lvl, ref[lvl], avx[lvl], ref[lvl]/avx[lvl]
    }
  }
}' "$CSV_PATH" | sort -t, -k1,1n
