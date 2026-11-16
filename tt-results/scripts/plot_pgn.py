"""Plot the Poneglyph comparison: TruthTable (on `_pgn` query variants) vs
PoneglyphDB vs the no-proof baseline (on the same `_pgn` queries),
side-by-side per query.

Reads tidy/tpch_pgn.csv (TT and Poneglyph; both use Q=q{N}, System
distinguishes them) and tidy/tpch_baseline.csv (variant=pgn). Prover time and
proof size are on log axes: the baseline's are milliseconds and megabytes. The
prover panel also has plain execution: the query on the full tables,
unverified.

Outputs:
  figures/tpch_pgn_combined.pdf — single PDF with prover time, verifier time,
                                   and proof size side-by-side, sharing one legend.
  figures/tpch_pgn_prover.pdf, tpch_pgn_verifier.pdf, tpch_pgn_proof_size.pdf
                                 — the same three panels as standalone figures.

Usage:
  python3 tt-results/scripts/plot_pgn.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter, LogLocator

import baseline_style

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

# Scale factor at which both systems have numbers (largest dataset both ran).
SCALE_FACTOR = 0.04

base_dir = Path(__file__).resolve().parent.parent
data_path = base_dir / "tidy" / "tpch_pgn.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("﻿") for c in df.columns]
df["Q"] = df["Q"].str.strip().str.lower()
df["System"] = df["System"].str.strip().str.lower()
df["scale-factor"] = pd.to_numeric(df["scale-factor"], errors="coerce")
for col in [
    "prover time 1thread (s)",
    "total verifier time (ms)",
    "core verifier time (ms)",
    "total proof size (KB)",
    "proof size core(KB)",
]:
    df[col] = pd.to_numeric(df[col], errors="coerce")

df = df[df["scale-factor"] == SCALE_FACTOR].copy()

query_ids = [1, 3, 5, 8, 9, 18]
query_labels = [f"Q{q}" for q in query_ids]

# (display label, System value in CSV). Both look up by Q=q{N}; the System
# column is what differentiates the two bars in each group.
series_specs = [
    ("TT simplified", "tt"),
    ("Poneglyph simplified", "poneglyph"),
    (f"{baseline_style.LABEL} simplified", "baseline"),
    (f"{baseline_style.EXEC_LABEL} simplified", "execution"),
]


def panel_specs(value_key):
    """Plain execution has only a time, shown next to the provers."""
    return [spec for spec in series_specs if spec[1] != "execution" or value_key == "prover"]

baseline = baseline_style.tpch("pgn", SCALE_FACTOR)
BASELINE_COLUMNS = {
    "prover": "prover time 1thread (s)",
    "verifier": "verifier time 1thread (ms)",
    "proof_size": "proof size (KB)",
}


def metric_column(system, value_key):
    if value_key == "prover":
        return "prover time 1thread (s)"
    if value_key == "verifier":
        # TT reports a crypto-only verifier time; Poneglyph only reports total.
        return "total verifier time (ms)" if system == "poneglyph" else "core verifier time (ms)"
    if value_key == "proof_size":
        # Poneglyph proofs aren't split into crypto/non-crypto; use total.
        return "total proof size (KB)" if system == "poneglyph" else "proof size core(KB)"
    raise ValueError(f"Unknown metric key: {value_key}")


def pick_value(q_num, system, value_key):
    if system == "baseline":
        return baseline_style.value(baseline, q_num, BASELINE_COLUMNS[value_key])
    if system == "execution":
        return baseline_style.value(baseline, q_num, "execution time 1thread (s)")
    row = df[(df["Q"] == f"q{q_num}") & (df["System"] == system)]
    if row.empty:
        return np.nan
    return float(row[metric_column(system, value_key)].iloc[0])


def build_series(value_key):
    return [
        [pick_value(q, system, value_key) for q in query_ids]
        for _, system in panel_specs(value_key)
    ]


colors = plt.get_cmap("tab10").colors
light_colors = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]
hatches = ["/", "x", "\\"]


def bar_style(i, system):
    if system == "baseline":
        return baseline_style.BAR_STYLE
    if system == "execution":
        return baseline_style.EXEC_BAR_STYLE
    return dict(facecolor=light_colors[i], edgecolor=colors[i], hatch=hatches[i], linewidth=0.8)


def draw_panel(ax, value_key, ylabel):
    specs = panel_specs(value_key)
    series = build_series(value_key)

    group_gap = 0.18
    bar_width = 0.16
    group_width = len(specs) * bar_width + group_gap
    x = np.arange(len(query_ids)) * group_width

    for i, ((_, system), heights) in enumerate(zip(specs, series)):
        ax.bar(x + i * bar_width, heights, width=bar_width, **bar_style(i, system))

    ax.set_xticks(x + bar_width * (len(specs) - 1) / 2, query_labels)
    if value_key in ("prover", "proof_size"):
        ax.set_yscale("log")
        ax.yaxis.set_major_locator(LogLocator(base=10))
        ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.set_xlabel("TPC-H Query")
    ax.set_ylabel(ylabel)
    ax.tick_params(axis="x", pad=10)
    ax.tick_params(axis="y", pad=10)
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)


panels = [
    ("prover", "Prover Time (s)", "tpch_pgn_prover.pdf"),
    ("verifier", "Verifier Time (ms)", "tpch_pgn_verifier.pdf"),
    ("proof_size", "Proof Size (KB)", "tpch_pgn_proof_size.pdf"),
]

def legend_style(value_key="prover", ncol=None):
    specs = panel_specs(value_key)
    return dict(
        handles=[
            plt.Rectangle((0, 0), 1, 1, **bar_style(i, system))
            for i, (_, system) in enumerate(specs)
        ],
        labels=[label for label, _ in specs],
        ncol=ncol or len(specs),
        loc="lower center",
        handlelength=2.2,
        handleheight=1.4,
        borderpad=0.6,
        columnspacing=1.6,
    )


# Width chosen so each subplot's aspect ratio matches the original single-panel
# figsize (10, 5.2 → 1.92:1). With height 8, each subplot wants ~15.4 wide, so
# total width ≈ 46.
PANEL_FIGSIZE = (15.4, 8)

fig, axes = plt.subplots(1, 3, figsize=(46, 8))
for ax, (key, ylabel, _) in zip(axes, panels):
    draw_panel(ax, key, ylabel)

# Single shared legend, centered below all three panels.
fig.legend(bbox_to_anchor=(0.5, -0.02), **legend_style())

# Reserve room at the bottom for the figure-level legend.
fig.tight_layout(rect=[0, 0.10, 1, 1])
fig.savefig(figures_dir / "tpch_pgn_combined.pdf", bbox_inches="tight")
plt.close(fig)

# Standalone per-metric figures, legend above the axes.
for key, ylabel, filename in panels:
    fig, ax = plt.subplots(figsize=PANEL_FIGSIZE)
    draw_panel(ax, key, ylabel)
    # Two columns: a 15-inch panel does not fit the labels in one row.
    ax.legend(bbox_to_anchor=(0.5, 1.02), **legend_style(key, ncol=2))
    fig.tight_layout()
    fig.savefig(figures_dir / filename, bbox_inches="tight")
    plt.close(fig)
