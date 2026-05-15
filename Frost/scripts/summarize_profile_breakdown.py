#!/usr/bin/env python3
"""Summarize optional Frost breakdown profiling CSVs.

Input raw CSV format:
  scheme,level,mode,backend,component,cycles,iterations,status,notes

Summary CSV keeps cycles. The LaTeX fragment renders selected columns in kCycles.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

SUMMARY_FIELDS = [
    "scheme", "level", "mode", "backend",
    "KEM_KeyGen", "KEM_Encaps", "KEM_Decaps",
    "PKE_KeyGen", "PKE_Enc", "PKE_Dec",
    "Expand_A", "A_times_S", "AT_times_R", "BhatT_times_R", "ST_times_U",
    "Dither", "Quant_Recon", "Pack_Unpack", "Hash_KDF",
]

TABLE_FIELDS = [
    ("Level", None),
    ("Implementation", None),
    ("KEM KG", "KEM_KeyGen"),
    ("KEM Enc", "KEM_Encaps"),
    ("KEM Dec", "KEM_Decaps"),
    ("Expand A", "Expand_A"),
    ("A S", "A_times_S"),
    ("A^T R", "AT_times_R"),
    ("B^T R", "BhatT_times_R"),
    ("S^T U", "ST_times_U"),
    ("Dither", "Dither"),
    ("Quant/Recon", "Quant_Recon"),
    ("Hash/Pack", "Hash_Pack"),
]


def fmt_num(value: float | None) -> str:
    if value is None:
        return "NA"
    return str(int(round(value)))


def fmt_kcycles(value: float | None) -> str:
    if value is None:
        return "NA"
    return f"{value / 1000.0:.1f}"


def sum_components(comp: dict[str, float], names: list[str]) -> float | None:
    present = [comp[n] for n in names if n in comp]
    if not present:
        return None
    return sum(present)


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: summarize_profile_breakdown.py RAW.csv SUMMARY.csv TABLE.tex", file=sys.stderr)
        return 2
    raw_path, summary_path, table_path = map(Path, argv[1:])
    rows: dict[tuple[str, str, str, str], dict[str, float]] = {}
    with raw_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("status") != "ok":
                continue
            key = (row["scheme"], row["level"], row["mode"], row["backend"])
            comp = rows.setdefault(key, {})
            comp[row["component"]] = comp.get(row["component"], 0.0) + float(row["cycles"])

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    table_path.parent.mkdir(parents=True, exist_ok=True)

    summary_rows = []
    mode_order = {"REFERENCE": 0, "FAST": 1}
    for key in sorted(rows, key=lambda k: (int(k[1]), mode_order.get(k[2], 99), k[3])):
        scheme, level, mode, backend = key
        comp = rows[key]
        vals: dict[str, float | None] = {
            "KEM_KeyGen": comp.get("KEM_KeyGen"),
            "KEM_Encaps": comp.get("KEM_Encaps"),
            "KEM_Decaps": comp.get("KEM_Decaps"),
            "PKE_KeyGen": comp.get("PKE_KeyGen"),
            "PKE_Enc": comp.get("PKE_Enc"),
            "PKE_Dec": comp.get("PKE_Dec"),
            "Expand_A": comp.get("Expand_A"),
            "A_times_S": comp.get("A_times_S"),
            "AT_times_R": comp.get("AT_times_R"),
            "BhatT_times_R": comp.get("BhatT_times_R"),
            "ST_times_U": comp.get("ST_times_U"),
            "Dither": sum_components(comp, ["Dither_PK", "Dither_U", "Dither_V"]),
            "Quant_Recon": sum_components(comp, ["Quant_PK", "Quant_U", "Quant_V", "Recon_PK", "Recon_U", "Recon_V"]),
            "Pack_Unpack": sum_components(comp, ["Pack_PK", "Unpack_PK", "Pack_CT", "Unpack_CT", "Pack_SK", "Unpack_SK"]),
            "Hash_KDF": sum_components(comp, ["FO_Hash", "PK_Hash", "KDF"]),
        }
        vals["Hash_Pack"] = sum_components(comp, ["FO_Hash", "PK_Hash", "KDF", "Pack_PK", "Unpack_PK", "Pack_CT", "Unpack_CT", "Pack_SK", "Unpack_SK"])
        summary_rows.append((key, vals))

    with summary_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        for (scheme, level, mode, backend), vals in summary_rows:
            out = {"scheme": scheme, "level": level, "mode": mode, "backend": backend}
            for field in SUMMARY_FIELDS[4:]:
                out[field] = fmt_num(vals.get(field))
            writer.writerow(out)

    with table_path.open("w") as f:
        f.write("% Generated from Frost/benchmarks/breakdown_profile.csv. Values are kCycles.\n")
        f.write("\\begin{tabular}{rrrrrrrrrrrrr}\n")
        f.write("\\toprule\n")
        f.write(" & ".join(title for title, _ in TABLE_FIELDS) + " " + (chr(92) * 2) + "\n")
        f.write("\\midrule\n")
        for (scheme, level, mode, backend), vals in summary_rows:
            impl = f"{mode}/{backend}"
            cells = [level, impl]
            for _, field in TABLE_FIELDS[2:]:
                cells.append(fmt_kcycles(vals.get(field)))
            f.write(" & ".join(cells) + " " + (chr(92) * 2) + "\n")
        f.write("\\bottomrule\n")
        f.write("\\end{tabular}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
