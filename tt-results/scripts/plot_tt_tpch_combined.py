"""Combined 2×2 figure: TPC-H prover, proof size, verifier, and per-table commit.

Reads:
  tidy/tpch.csv    — TPC-H prover/verifier/proof-size rows (System=tt)
  tidy/commit.csv  — per-table commit latency

Output:
  figures/tpch_tt_combined.pdf

Layout:
  ┌──────────────────┬──────────────────┐
  │  Prover time     │  Proof size      │
  │  (1t/4t bars)    │  (single bar)    │
  ├──────────────────┼──────────────────┤
  │  Verifier time   │  Commit latency  │
  │  (crypto/non-cr) │  (per table)     │
  └──────────────────┴──────────────────┘

Usage:
  python3 tt-results/scripts/plot_tt_tpch_combined.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyBboxPatch
from matplotlib.ticker import FuncFormatter, LogLocator

plt.style.use("seaborn-v0_8-whitegrid")
# Bumped ~1.4× from the previous "moderate" sizing per user feedback that the
# combined-plot fonts read small. Still smaller than the standalone micro/pgn
# plots (which use 2.25×) because each panel hosts up to 17 tick labels.
# Single uniform font size across all text in this figure (base, axis labels,
# tick labels, legend). Other plot scripts share the same setting.
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
# Full TPC-H range; we filter down to supported queries after loading the CSV.
_FULL_QUERY_RANGE = list(range(1, 23))

base_dir = Path(__file__).resolve().parent.parent
tpch_path = base_dir / "tidy" / "tpch.csv"
commit_path = base_dir / "tidy" / "commit.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

# ── Load TPC-H rows ───────────────────────────────────────────────────
tdf = pd.read_csv(tpch_path)
tdf.columns = [c.strip().lstrip("﻿") for c in tdf.columns]
tdf["Q"] = tdf["Q"].str.strip().str.lower()
tdf["System"] = tdf["System"].str.strip().str.lower()
tdf["scale-factor"] = pd.to_numeric(tdf["scale-factor"], errors="coerce")
for col in [
    "prover time 1thread (s)",
    "prover time 4threads (s)",
    "total verifier time (ms)",
    "core verifier time (ms)",
    "preprocessed veritifier time (ms)",
    "total proof size (KB)",
]:
    tdf[col] = pd.to_numeric(tdf[col], errors="coerce")
tdf = tdf[(tdf["System"] == "tt") & (tdf["scale-factor"] == SCALE_FACTOR)].copy()
# Drop unsupported queries entirely (no empty x-axis slot for them).
QUERY_IDS = [q for q in _FULL_QUERY_RANGE if not tdf[tdf["Q"] == f"q{q}"].empty]
query_labels = [str(q) for q in QUERY_IDS]


def tlookup(q_num, col):
    row = tdf[tdf["Q"] == f"q{q_num}"]
    if row.empty:
        return float("nan")
    return float(row[col].iloc[0])


def tvalues(col):
    return [tlookup(q, col) for q in QUERY_IDS]


def _style_q_axes(ax):
    ax.set_xlabel("TPC-H Query")
    ax.tick_params(axis="x", pad=8)
    ax.tick_params(axis="y", pad=8)
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)


colors = plt.get_cmap("tab10").colors
light = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]


def draw_prover(ax):
    one = tvalues("prover time 1thread (s)")
    bar_width = 0.7
    x = np.arange(len(QUERY_IDS), dtype=float)
    ax.bar(x, one, width=bar_width, facecolor=light[0], edgecolor=colors[0],
           hatch="/", linewidth=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Prover Time (s)")
    _style_q_axes(ax)
    ymax = float(np.nanmax(np.asarray(one, dtype=float)))
    ax.set_ylim(0, ymax * 1.10)


def draw_proof_size(ax):
    sizes = tvalues("total proof size (KB)")
    bar_width = 0.7
    x = np.arange(len(QUERY_IDS), dtype=float)
    ax.bar(x, sizes, width=bar_width, facecolor=light[4], edgecolor=colors[4],
           hatch="x", linewidth=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Proof Size (KB)")
    _style_q_axes(ax)
    ymax = float(np.nanmax(np.asarray(sizes, dtype=float)))
    ax.set_ylim(0, ymax * 1.10)


def draw_verifier(ax):
    total = tvalues("total verifier time (ms)")
    bar_width = 0.7
    x = np.arange(len(QUERY_IDS), dtype=float)
    ax.bar(x, total, width=bar_width, facecolor=light[2], edgecolor=colors[2],
           hatch="/", linewidth=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Verifier Time (ms)")
    _style_q_axes(ax)
    ymax = float(np.nanmax(np.asarray(total, dtype=float)))
    ax.set_ylim(0, ymax * 1.10)


# ── Load commit rows ──────────────────────────────────────────────────
cdf = pd.read_csv(commit_path)
cdf.columns = [c.strip().lstrip("﻿") for c in cdf.columns]
cdf["table"] = cdf["table"].astype(str).str.strip().str.lower()
cdf["scale-factor"] = pd.to_numeric(cdf["scale-factor"], errors="coerce")
cdf["latency-1thread(ms)"] = pd.to_numeric(cdf["latency-1thread(ms)"], errors="coerce")
cdf = cdf[cdf["scale-factor"] == SCALE_FACTOR].copy()
if cdf.empty:
    raise RuntimeError(f"no rows with scale-factor={SCALE_FACTOR} in {commit_path}")
cdf = cdf.sort_values("table").reset_index(drop=True)

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
cdf["abbrev"] = cdf["table"].map(TABLE_ABBREV)


def draw_commit(ax):
    # Distinct color + hatch from the other three panels:
    # prover (blue /), verifier (green /), proof (purple x) → commit (orange \).
    palette_face = light[1]
    palette_edge = colors[1]
    x = np.arange(len(cdf))
    ax.bar(x, cdf["latency-1thread(ms)"] / 1000.0, width=0.7,
           facecolor=palette_face, edgecolor=palette_edge, hatch="\\", linewidth=0.8)
    ax.set_xticks(x, cdf["abbrev"].tolist())
    ax.set_xlabel("Table")
    ax.set_ylabel("Commit Latency (s)")
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.tick_params(axis="x", pad=10)
    ax.tick_params(axis="y", pad=10)
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)
    # Abbreviation legend, top-right. Drawn as a background box + per-cell
    # ax.text calls; each "=" sign is right-anchored at a fixed column x, so
    # columns line up regardless of font metrics. (Earlier single-string +
    # monospace attempts misaligned because matplotlib right-aligns each line
    # of a multi-line block individually when ha="right".)
    abbrev_rows = [
        ("C",  "customer", "P",  "part"),
        ("L",  "lineitem", "PS", "partsupp"),
        ("N",  "nation",   "R",  "region"),
        ("O",  "orders",   "S",  "supplier"),
    ]
    # Each row's full "key = value" string is left-anchored at the column's
    # x_start, so every row in a column begins at the same x. The "=" signs
    # will sit at slightly different positions across rows (intended).
    # Box widened further left to accommodate 38pt text with comfortable
    # right margin and inter-column gap. The new bx0=0.42 slightly overlaps
    # the very top corner of the orders bar (y~0.67), but alpha=0.95 keeps
    # the impact small.
    bx0, by0, bx1, by1 = 0.42, 0.59, 0.985, 0.955
    ax.add_patch(FancyBboxPatch(
        (bx0, by0), bx1 - bx0, by1 - by0,
        boxstyle="round,pad=0.005",
        transform=ax.transAxes,
        facecolor="white", edgecolor="#bbbbbb",
        linewidth=1.0, alpha=0.95,
        zorder=4,
    ))
    left_start = 0.44
    right_start = 0.70
    margin_y = 0.04
    y_positions = np.linspace(by1 - margin_y, by0 + margin_y, len(abbrev_rows))
    for y, (k1, v1, k2, v2) in zip(y_positions, abbrev_rows):
        ax.text(left_start,  y, f"{k1} = {v1}", transform=ax.transAxes,
                ha="left", va="center", fontsize=38, zorder=5)
        ax.text(right_start, y, f"{k2} = {v2}", transform=ax.transAxes,
                ha="left", va="center", fontsize=38, zorder=5)


fig, axes = plt.subplots(2, 2, figsize=(36, 16))
# Layout: commit + verifier on top, prover + proof size on bottom.
draw_commit(axes[0, 0])
draw_verifier(axes[0, 1])
draw_prover(axes[1, 0])
draw_proof_size(axes[1, 1])

fig.tight_layout()
fig.savefig(figures_dir / "tpch_tt_combined.pdf", bbox_inches="tight")
plt.close(fig)
