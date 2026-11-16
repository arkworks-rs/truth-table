"""Combined 2×2 figure: TPC-H prover, proof size, verifier, and per-table commit,
each next to the no-proof baseline.

Reads:
  tidy/tpch.csv             — TPC-H prover/verifier/proof-size rows (System=tt)
  tidy/commit.csv           — per-table commit latency
  tidy/tpch_baseline.csv    — the baseline on the same `_tt` queries
  tidy/commit_baseline.csv  — the baseline's per-table commit latency

Output:
  figures/tpch_tt_combined.pdf

Layout:
  ┌──────────────────┬──────────────────┐
  │  Prover time     │  Proof size      │
  │  (1 thread)      │                  │
  ├──────────────────┼──────────────────┤
  │  Verifier time   │  Commit latency  │
  │  (1 thread)      │  (per table)     │
  └──────────────────┴──────────────────┘

Usage:
  python3 tt-results/scripts/plot_tt_tpch_combined.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter, LogLocator

import baseline_style

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

baseline = baseline_style.tpch("tt", SCALE_FACTOR)
BAR_WIDTH = 0.38


def _log_axis(ax, values):
    arr = np.asarray(values, dtype=float)
    ax.set_yscale("log")
    ax.set_ylim(np.nanmin(arr) / 2, np.nanmax(arr) * 3)
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))


def draw_query_panel(ax, tt, base, color_idx, hatch, ylabel, log):
    """TruthTable's bar and the baseline's bar for every query."""
    x = np.arange(len(QUERY_IDS), dtype=float)
    ax.bar(x, tt, width=BAR_WIDTH, facecolor=light[color_idx],
           edgecolor=colors[color_idx], hatch=hatch, linewidth=0.8)
    ax.bar(x + BAR_WIDTH, base, width=BAR_WIDTH, **baseline_style.BAR_STYLE)
    ax.set_xticks(x + BAR_WIDTH / 2)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel(ylabel)
    _style_q_axes(ax)
    if log:
        _log_axis(ax, tt + base)
    else:
        ax.set_ylim(0, float(np.nanmax(np.asarray(tt + base, dtype=float))) * 1.10)


def bvalues(col):
    return [baseline_style.value(baseline, q, col) for q in QUERY_IDS]


def draw_prover(ax):
    draw_query_panel(ax, tvalues("prover time 1thread (s)"),
                     bvalues("prover time 1thread (s)"), 0, "/", "Prover Time (s)", True)


def draw_proof_size(ax):
    draw_query_panel(ax, tvalues("total proof size (KB)"), bvalues("proof size (KB)"),
                     4, "x", "Proof Size (KB)", True)


def draw_verifier(ax):
    draw_query_panel(ax, tvalues("total verifier time (ms)"),
                     bvalues("verifier time 1thread (ms)"), 2, "/", "Verifier Time (ms)",
                     False)


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
commit_baseline = baseline_style.commit(SCALE_FACTOR)

def draw_commit(ax):
    # Distinct color + hatch from the other three panels:
    # prover (blue /), verifier (green /), proof (purple x) → commit (orange \).
    palette_face = light[1]
    palette_edge = colors[1]
    x = np.arange(len(cdf))
    seconds = (cdf["latency-1thread(ms)"] / 1000.0).tolist()
    base_seconds = [
        baseline_style.value(commit_baseline, t, "latency-1thread(ms)") / 1000.0
        for t in cdf["table"]
    ]
    ax.bar(x, seconds, width=BAR_WIDTH,
           facecolor=palette_face, edgecolor=palette_edge, hatch="\\", linewidth=0.8)
    ax.bar(x + BAR_WIDTH, base_seconds, width=BAR_WIDTH, **baseline_style.BAR_STYLE)
    # Full table names on the axis: an abbreviation key inside the panel
    # covers the bars once the larger tables pass a few seconds.
    ax.set_xticks(x + BAR_WIDTH / 2, cdf["table"].tolist(), fontsize="small")
    ax.set_xlabel("Table")
    ax.set_ylabel("Commit Latency (s)")
    _log_axis(ax, seconds + base_seconds)
    ax.tick_params(axis="x", pad=10)
    ax.tick_params(axis="y", pad=10)
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)


# figsize_width matches plot_pgn.py / plot_micro.py (46), and figsize_height
# = 2 × the others' per-subplot height (2×8=16). With 2 rows this gives the
# same per-subplot display height as the 1-row PDFs when viewed at equal
# screen width, so subplots no longer appear taller in the combined figure.
fig, axes = plt.subplots(2, 2, figsize=(46, 16))
# Layout: commit + verifier on top, prover + proof size on bottom.
draw_commit(axes[0, 0])
draw_verifier(axes[0, 1])
draw_prover(axes[1, 0])
draw_proof_size(axes[1, 1])

# TruthTable's bars take each panel's color; the baseline's are the same in
# every panel.
fig.legend(
    handles=[
        Patch(facecolor="white", edgecolor="black", linewidth=0.8, label="TruthTable (colored)"),
        Patch(label=baseline_style.LABEL, **baseline_style.BAR_STYLE),
    ],
    ncol=2,
    loc="lower center",
    bbox_to_anchor=(0.5, 1.0),
    handlelength=2.2,
    handleheight=1.4,
    borderpad=0.6,
    columnspacing=1.6,
)

fig.tight_layout()
fig.savefig(figures_dir / "tpch_tt_combined.pdf", bbox_inches="tight")
plt.close(fig)
