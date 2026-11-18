"""Rebuild tidy/commit.csv from TruthTable's commit bench (run by
run_tt_tpch.sh).

Reads, for every scale factor with both thread counts present:
  raw/benches_commit_{sf}_{1,4}.json  — divan medians
  raw/commit_{sf}_1.txt               — the bench's commitment-size lines

Only the hash-only tables (`bench_tpch_commit_content`) are kept; the
`_tt_2` group commits the white-box string columns the TruthTable figures
leave out.

Usage:
  python3 tt-results/scripts/parse_tt_commit.py
"""

import json
import re
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "raw"
OUT = RAW.parent / "tidy" / "commit.csv"
GROUP = "bench_tpch_commit_content"
UNITS = {"ns": 1e-6, "µs": 1e-3, "us": 1e-3, "ms": 1.0, "s": 1e3, "m": 60e3}


def medians(path):
    group = json.loads(path.read_text())["benches"]["commit"][GROUP]
    out = {}
    for key, value in group.items():
        number, unit = value["time"]["median"].split()
        out[re.search(r'table: "(\w+)"', key).group(1)] = float(number) * UNITS[unit]
    return out


def sizes_kb(path):
    pattern = re.compile(r"tracked table oracle size \(commit_(\w+)\) = (\d+) bytes")
    return {
        m.group(1): int(m.group(2)) / 1024
        for m in map(pattern.search, path.read_text().splitlines())
        if m and not m.group(1).endswith("_tt_2")
    }


sfs = sorted(
    {p.name.split("_")[2] for p in RAW.glob("benches_commit_*_1.json")},
    key=float,
    reverse=True,
)
rows = ["table,scale-factor,latency-1thread(ms),latency-4thread(ms),size(KB)"]
for sf in sfs:
    four_path = RAW / f"benches_commit_{sf}_4.json"
    if not four_path.exists():
        print(f"SF {sf}: no 4-thread run, skipped")
        continue
    one, four = medians(RAW / f"benches_commit_{sf}_1.json"), medians(four_path)
    size = sizes_kb(RAW / f"commit_{sf}_1.txt")
    for table in sorted(one):
        rows.append(f"{table},{sf},{one[table]:.1f},{four[table]:.1f},{size[table]:.1f}")
OUT.write_text("\n".join(rows) + "\n")
print(f"Wrote {OUT}: {len(rows) - 1} rows")
