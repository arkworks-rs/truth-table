"""Plot the Poneglyph comparison: TruthTable (on `_pgn` query variants) vs
PoneglyphDB, side-by-side per query.

Reads tidy/tpch_pgn.csv. Both systems use Q=q{N} in that CSV; System
distinguishes which prover produced the row.

Output:
  figures/tpch_pgn_combined.pdf — single PDF with prover time, verifier time,
                                   and proof size side-by-side, sharing one legend.

Usage:
  python3 tt-results/scripts/plot_pgn.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

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
]


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
    row = df[(df["Q"] == f"q{q_num}") & (df["System"] == system)]
    if row.empty:
        return np.nan
    return float(row[metric_column(system, value_key)].iloc[0])


def build_series(value_key):
    return [
        [pick_value(q, system, value_key) for q in query_ids]
        for _, system in series_specs
    ]


colors = plt.get_cmap("tab10").colors
light_colors = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]
hatches = ["/", "x", "\\"]


def draw_panel(ax, value_key, ylabel):
    series = build_series(value_key)

    group_gap = 0.18
    bar_width = 0.16
    group_width = len(series_specs) * bar_width + group_gap
    x = np.arange(len(query_ids)) * group_width

    for i, ((_, _system), heights) in enumerate(zip(series_specs, series)):
        ax.bar(
            x + i * bar_width,
            heights,
            width=bar_width,
            alpha=1.0,
            facecolor=light_colors[i],
            edgecolor=colors[i],
            hatch=hatches[i],
            linewidth=0.8,
        )

    ax.set_xticks(x + bar_width, query_labels)
    ax.set_xlabel("TPC-H Query")
    ax.set_ylabel(ylabel)
    ax.tick_params(axis="x", pad=10)
    ax.tick_params(axis="y", pad=10)
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)


# Width chosen so each subplot's aspect ratio matches the original single-panel
# figsize (10, 5.2 → 1.92:1). With height 8, each subplot wants ~15.4 wide, so
# total width ≈ 46.
fig, axes = plt.subplots(1, 3, figsize=(46, 8))
panels = [
    ("prover", "Prover Time (s)"),
    ("verifier", "Verifier Time (ms)"),
    ("proof_size", "Proof Size (KB)"),
]
for ax, (key, ylabel) in zip(axes, panels):
    draw_panel(ax, key, ylabel)

# Single shared legend, centered below all three panels.
legend_handles = [
    plt.Rectangle(
        (0, 0),
        1,
        1,
        facecolor=light_colors[i],
        edgecolor=colors[i],
        hatch=hatches[i],
        linewidth=0.8,
    )
    for i in range(len(series_specs))
]
legend_labels = [label for label, _ in series_specs]

fig.legend(
    handles=legend_handles,
    labels=legend_labels,
    ncol=len(series_specs),
    loc="lower center",
    bbox_to_anchor=(0.5, -0.02),
    handlelength=2.2,
    handleheight=1.4,
    borderpad=0.6,
    columnspacing=1.6,
)

# Reserve room at the bottom for the figure-level legend.
fig.tight_layout(rect=[0, 0.10, 1, 1])
fig.savefig(figures_dir / "tpch_pgn_combined.pdf", bbox_inches="tight")
plt.close(fig)
