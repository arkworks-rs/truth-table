"""Plot single-threaded prover time per TPC-H query for TruthTable and
PoneglyphDB on one bar chart, at SF 0.04 (the largest SF Poneglyph supports).

Every query TT runs gets a TT bar. Queries Poneglyph does not support get a
red cross in place of the Poneglyph bar.

Sources:
  tidy/tpch_pgn.csv        — TT and Poneglyph on the six Poneglyph queries
                             (Q1, Q3, Q5, Q8, Q9, Q18). TT runs the `_pgn`
                             variants here, so both bars prove the same query;
                             these ticks are starred.
  raw/benches_tt_0.04_1.json — TT on the regular `_tt` queries at SF 0.04,
                             used for the queries Poneglyph does not support.
                             No parse script reads it for SF 0.04.

Outputs:
  figures/tpch_tt_vs_pgn_prover.pdf

Usage:
  python3 tt-results/scripts/plot_tpch_vs_pgn.py
"""

import json
import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch

plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams.update(
    {
        "font.size": 38,
        "axes.labelsize": 38,
        "xtick.labelsize": 38,
        "ytick.labelsize": 38,
        "legend.fontsize": 38,
        "hatch.linewidth": 0.6,
    }
)

SCALE_FACTOR = 0.04

# Every TPC-H query TT has a `_tt` bench for.
QUERY_IDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 17, 18, 19, 20]
PGN_QUERY_IDS = {1, 3, 5, 8, 9, 18}

FIGSIZE = (46, 8)

base_dir = Path(__file__).resolve().parent.parent
pgn_csv_path = base_dir / "tidy" / "tpch_pgn.csv"
tt_bench_path = base_dir / "raw" / "benches_tt_0.04_1.json"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)


def parse_time_to_seconds(s):
    m = re.match(r"([\d.]+)\s*([a-zµ]+)", s.strip())
    v, u = float(m.group(1)), m.group(2)
    return {"m": v * 60, "s": v, "ms": v / 1000, "µs": v / 1e6, "us": v / 1e6}[u]


df = pd.read_csv(pgn_csv_path)
df.columns = [c.strip().lstrip("﻿") for c in df.columns]
df["Q"] = df["Q"].str.strip().str.lower()
df["System"] = df["System"].str.strip().str.lower()
df["scale-factor"] = pd.to_numeric(df["scale-factor"], errors="coerce")
df["prover time 1thread (s)"] = pd.to_numeric(df["prover time 1thread (s)"], errors="coerce")
df = df[df["scale-factor"] == SCALE_FACTOR]

tt_cases = json.loads(tt_bench_path.read_text())["benches"]["tpch"]


def pgn_csv_value(q_num, system):
    row = df[(df["Q"] == f"q{q_num}") & (df["System"] == system)]
    if row.empty:
        return np.nan
    return float(row["prover time 1thread (s)"].iloc[0])


def tt_value(q_num):
    if q_num in PGN_QUERY_IDS:
        return pgn_csv_value(q_num, "tt")
    case = tt_cases.get(f"tpch_q{q_num}_tt")
    if case is None:
        return np.nan
    return parse_time_to_seconds(case["prover"]["time"]["median"])


tt_times = [tt_value(q) for q in QUERY_IDS]
pgn_times = [pgn_csv_value(q, "poneglyph") for q in QUERY_IDS]
query_labels = [f"Q{q}*" if q in PGN_QUERY_IDS else f"Q{q}" for q in QUERY_IDS]

colors = plt.get_cmap("tab10").colors
light = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]
tt_idx, pgn_idx = 0, 1

bar_width = 0.38
group_gap = 0.30
group_width = 2 * bar_width + group_gap
x = np.arange(len(QUERY_IDS)) * group_width

fig, ax = plt.subplots(figsize=FIGSIZE)
ax.bar(
    x,
    tt_times,
    width=bar_width,
    facecolor=light[tt_idx],
    edgecolor=colors[tt_idx],
    hatch="/",
    linewidth=0.8,
)
ax.bar(
    x + bar_width,
    pgn_times,
    width=bar_width,
    facecolor=light[pgn_idx],
    edgecolor=colors[pgn_idx],
    hatch="x",
    linewidth=0.8,
)

# Red cross on the baseline where Poneglyph has no bar.
unsupported_x = [x[i] + bar_width for i, q in enumerate(QUERY_IDS) if q not in PGN_QUERY_IDS]
cross = ax.scatter(
    unsupported_x,
    [0.02] * len(unsupported_x),
    marker="X",
    s=200,
    color="red",
    linewidths=2.0,
    edgecolors="red",
    zorder=5,
    transform=ax.get_xaxis_transform(),
    clip_on=False,
)

ax.set_xticks(x + bar_width / 2)
ax.set_xticklabels(query_labels)
ax.set_xlabel("TPC-H Query")
ax.set_ylabel("Prover Time (s)")
ax.tick_params(axis="x", pad=8)
ax.tick_params(axis="y", pad=8)
ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)
ax.set_xlim(x[0] - bar_width, x[-1] + 2 * bar_width)
ax.set_ylim(0, np.nanmax(tt_times + pgn_times) * 1.10)

ax.legend(
    [
        Patch(facecolor=light[tt_idx], edgecolor=colors[tt_idx], hatch="/"),
        Patch(facecolor=light[pgn_idx], edgecolor=colors[pgn_idx], hatch="x"),
        cross,
    ],
    ["TruthTable", "Poneglyph", "Not supported by Poneglyph"],
    ncol=3,
    loc="lower center",
    bbox_to_anchor=(0.5, 1.04),
    handlelength=2.2,
    handleheight=1.4,
    borderpad=0.6,
    columnspacing=1.6,
)

fig.tight_layout()
fig.savefig(figures_dir / "tpch_tt_vs_pgn_prover.pdf", bbox_inches="tight")
plt.close(fig)
