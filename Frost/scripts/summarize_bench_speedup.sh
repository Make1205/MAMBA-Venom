#!/usr/bin/env bash
set -euo pipefail
CSV_PATH=${1:?"usage: $0 <bench.csv>"}
awk -F',' '
NR==1 { next }
$14=="ok" {
  level=$2; mode=$3; total=$8+0
  if (mode=="REFERENCE") ref[level]=total
  else if (mode=="AVX2" || mode=="FAST") fast[level]=total
}
END {
  printf "level,ref_total,fast_total,speedup(ref/fast)\n"
  for (lvl in ref) {
    if (lvl in fast && fast[lvl] > 0) {
      printf "%s,%.0f,%.0f,%.3f\n", lvl, ref[lvl], fast[lvl], ref[lvl]/fast[lvl]
    }
  }
}' "$CSV_PATH" | sort -t, -k1,1n
