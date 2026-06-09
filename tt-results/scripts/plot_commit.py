"""Plot per-table commit (oracle build) latency.

Reads tidy/commit.csv. Filtered to SF=0.1, 1-thread to match the recent
TPC-H baseline sweeps.

Output:
  figures/commit_time.pdf — single panel, one bar per table, log Y.

Usage:
  python3 tt-results/scripts/plot_commit.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter, LogLocator

plt.style.use("seaborn-v0_8-whitegrid")
# Match the font sizes used in plot_tt_tpch_combined.py so all plots share
# a consistent visual scale.
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

SCALE_FACTOR = 0.1

base_dir = Path(__file__).resolve().parent.parent
data_path = base_dir / "tidy" / "commit.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("﻿") for c in df.columns]
df["table"] = df["table"].astype(str).str.strip().str.lower()
df["scale-factor"] = pd.to_numeric(df["scale-factor"], errors="coerce")
df["latency-1thread(ms)"] = pd.to_numeric(df["latency-1thread(ms)"], errors="coerce")

df = df[df["scale-factor"] == SCALE_FACTOR].copy()
if df.empty:
    raise RuntimeError(f"no rows with scale-factor={SCALE_FACTOR} in {data_path}")
df = df.sort_values("table").reset_index(drop=True)

# TPC-H standard schema prefixes — compact x-tick labels at large font sizes.
TABLE_ABBREV = {
    "customer": "C",
    "lineitem": "L",
    "nation":   "N",
    "orders":   "O",
    "part":     "P",
    "partsupp": "PS",
    "region":   "R",
    "supplier": "S",
}
df["abbrev"] = df["table"].map(TABLE_ABBREV)

palette_face = "#d7e6f5"
palette_edge = "#1f77b4"

fig, ax = plt.subplots(figsize=(16, 8))
x = np.arange(len(df))
ax.bar(
    x,
    df["latency-1thread(ms)"] / 1000.0,
    width=0.7,
    facecolor=palette_face,
    edgecolor=palette_edge,
    hatch="/",
    linewidth=0.8,
)
ax.set_xticks(x, df["abbrev"].tolist())
ax.set_xlabel("Table")
ax.set_ylabel("Commit Latency (s)")
ax.set_yscale("log")
ax.yaxis.set_major_locator(LogLocator(base=10))
ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
ax.tick_params(axis="x", pad=10)
ax.tick_params(axis="y", pad=10)
ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)

# Two-line mapping caption below the figure. Smaller than the axis fonts so it
# reads as legend material, not chart data.
caption = (
    "C = customer    L = lineitem    N = nation    O = orders\n"
    "P = part    PS = partsupp    R = region    S = supplier"
)
fig.text(0.5, -0.02, caption, ha="center", va="top", fontsize=30)

fig.tight_layout()
fig.savefig(figures_dir / "commit_time.pdf", bbox_inches="tight")
plt.close(fig)
