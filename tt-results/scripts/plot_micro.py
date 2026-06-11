"""Plot the micro-benchmark comparison on the shared
Filter / Aggregate / Join / Join PK/FK / Limit operators.

Reads tidy/micro.csv.

Outputs (one per curve, since each Truth Table competitor only runs on one
of the two curves we support):
  figures/micro_bn254.pdf      — TT (BN254)      vs PoSQL
  figures/micro_bls12_381.pdf  — TT (BLS12-381)  vs QEDB

Each PDF has prover time, verifier time, and proof size side-by-side, sharing
one legend.

Usage:
  python3 tt-results/scripts/plot_micro.py
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

base_dir = Path(__file__).resolve().parent.parent
data_path = base_dir / "tidy" / "micro.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)


def normalize_q(name):
    q = str(name).strip().lower()
    if q == "limit offset":
        return "limit"
    if q in {"join pk/fk", "join pk fk"}:
        return "join_pk_fk"
    return q


df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("﻿") for c in df.columns]
df = df[(df["Q"] != "Q") & (df["System"] != "System")].copy()
df["table log size"] = pd.to_numeric(df["table log size"], errors="coerce")
df["threads"] = pd.to_numeric(df["threads"], errors="coerce")
df["prover time (s)"] = pd.to_numeric(df["prover time (s)"], errors="coerce")
df["verifier time (ms)"] = pd.to_numeric(df["verifier time (ms)"], errors="coerce")
df["proof size (KB)"] = pd.to_numeric(df["proof size (KB)"], errors="coerce")
df["q_norm"] = df["Q"].apply(normalize_q)
df["system_norm"] = df["System"].str.strip().str.lower()
# Curve column was added when we started running TT under both BN254 and
# BLS12-381. Older CSVs predate it — default to "bn254" so legacy rows still
# plot.
if "curve" in df.columns:
    df["curve_norm"] = df["curve"].astype(str).str.strip().str.lower()
else:
    df["curve_norm"] = "bn254"

# Fix to table log size 19. Pick the thread count present in the CSV (all rows
# share the same NUM_THREADS from run_micro.sh).
available_threads = sorted(df["threads"].dropna().unique())
if not available_threads:
    raise RuntimeError(f"no rows with a threads value in {data_path}")
threads_value = 1 if 1 in available_threads else int(available_threads[0])
df = df[(df["table log size"] == 19) & (df["threads"] == threads_value)].copy()
print(f"plot_micro: filtering to threads={threads_value}")


# Per-variant style. Each variant is one PDF and pairs TT @ that curve
# against the single competitor that natively runs on it.
#
# `operators` controls which operator groups appear in this variant's PDF.
VARIANTS = [
    {
        "curve": "bn254",
        "outfile": "micro_bn254.pdf",
        "tt_bar": "tt_bn254",
        "tt_label": "TT (BN254)",
        "competitor_bar": "posql",
        "competitor_label": "PoSQL",
        "operators": ("Filter", "Aggregate", "Join", "Limit"),
    },
    {
        "curve": "bls12_381",
        "outfile": "micro_bls12_381.pdf",
        "tt_bar": "tt_bls12_381",
        "tt_label": "TT (BLS12-381)",
        "competitor_bar": "qedb",
        "competitor_label": "QEDB",
        "operators": ("Filter", "Aggregate"),
        # Slightly wider gap between operator groups so the "Filter" /
        # "Aggregate" x-axis labels don't touch in the narrower 2-operator
        # layout.
        "group_gap": 0.35,
    },
]

# Shared color/hatch table. The same TT blue is reused across variants; only
# the hatch differs (single vs double slash) to mark the curve.
palette = {
    "tt_bn254": {"edge": "#1f77b4", "face": "#d7e6f5"},
    "tt_bls12_381": {"edge": "#1f77b4", "face": "#aacde9"},
    "tt_join_pk_fk_bn254": {"edge": "#1f77b4", "face": "#d7e6f5"},
    "tt_join_pk_fk_bls12_381": {"edge": "#1f77b4", "face": "#aacde9"},
    "posql": {"edge": "#e31a1c", "face": "#f9d6d6"},
    "qedb": {"edge": "#33a02c", "face": "#d9efd6"},
}
hatches = {
    "tt_bn254": "/",
    "tt_bls12_381": "//",
    "tt_join_pk_fk_bn254": "/",
    "tt_join_pk_fk_bls12_381": "//",
    "posql": "x",
    "qedb": "\\",
}


def pick_value(q_name, bar_key, value_col):
    """Resolve one (q, bar_key) cell into a value from the CSV."""
    if bar_key == "tt_bn254":
        row = df[
            (df["q_norm"] == q_name)
            & (df["system_norm"] == "tt")
            & (df["curve_norm"] == "bn254")
        ]
    elif bar_key == "tt_bls12_381":
        row = df[
            (df["q_norm"] == q_name)
            & (df["system_norm"] == "tt")
            & (df["curve_norm"] == "bls12_381")
        ]
    elif bar_key == "tt_join_pk_fk_bn254":
        row = df[
            (df["q_norm"] == q_name)
            & (df["system_norm"] == "tt")
            & (df["curve_norm"] == "bn254")
        ]
    elif bar_key == "tt_join_pk_fk_bls12_381":
        row = df[
            (df["q_norm"] == q_name)
            & (df["system_norm"] == "tt")
            & (df["curve_norm"] == "bls12_381")
        ]
    else:
        row = df[(df["q_norm"] == q_name) & (df["system_norm"] == bar_key)]
    if row.empty:
        return np.nan
    return float(row[value_col].iloc[0])


def build_groups(variant):
    """Operator groups for one variant, filtered to variant["operators"]."""
    tt_bar = variant["tt_bar"]
    pkfk_bar = f"tt_join_pk_fk_{variant['curve']}"
    competitor = variant["competitor_bar"]
    all_groups = {
        "Filter": {"label": "Filter", "bars": [(tt_bar, "filter"), (competitor, "filter")]},
        "Aggregate": {
            "label": "Aggregate",
            "bars": [(tt_bar, "aggregate"), (competitor, "aggregate")],
        },
        "Join": {
            "label": "Join",
            "bars": [
                (tt_bar, "join"),
                (pkfk_bar, "join_pk_fk"),
                (competitor, "join"),
            ],
        },
        "Limit": {"label": "Limit", "bars": [(tt_bar, "limit"), (competitor, "limit")]},
    }
    return [all_groups[name] for name in variant["operators"]]


BAR_WIDTH = 0.16
GROUP_GAP = 0.22

# Reference layout: the original 4-operator BN254 plot (Filter+Aggregate+Join+
# Limit = 9 bars across 4 groups) was tuned at figsize_width=46 inches. Scale
# any variant's figure width by its share of that reference x-extent so the
# bars keep their physical width on the page regardless of operator count.
REFERENCE_FIGSIZE_WIDTH = 46.0
REFERENCE_PANEL_X_EXTENT = 9 * BAR_WIDTH + 3 * GROUP_GAP


def panel_x_extent(groups, group_gap=GROUP_GAP):
    bars = sum(len(spec["bars"]) for spec in groups)
    gaps = max(0, len(groups) - 1)
    return bars * BAR_WIDTH + gaps * group_gap


def draw_panel(ax, groups, value_col, ylabel, group_gap=GROUP_GAP):
    bar_width = BAR_WIDTH
    group_centers = []
    # Center the bars inside a fixed reference x-extent so panels with fewer
    # operator groups (e.g. BLS12-381) keep the same per-bar display width and
    # the same panel/font scale as the wider variants instead of being
    # stretched up by figsize scaling.
    bars_x_extent = panel_x_extent(groups, group_gap)
    leading_pad = (REFERENCE_PANEL_X_EXTENT - bars_x_extent) / 2.0
    group_start = max(0.0, leading_pad)

    for spec in groups:
        bars = spec["bars"]
        offsets = np.arange(len(bars)) * bar_width
        for offset, (bar_key, q_name) in zip(offsets, bars):
            height = pick_value(q_name, bar_key, value_col)
            x_pos = group_start + offset
            ax.bar(
                x_pos,
                height,
                width=bar_width,
                alpha=1.0,
                facecolor=palette[bar_key]["face"],
                edgecolor=palette[bar_key]["edge"],
                hatch=hatches[bar_key],
                linewidth=0.8,
            )
            if bar_key.startswith("tt_join_pk_fk") and not np.isnan(height):
                ax.text(
                    x_pos,
                    height * 1.18,
                    "* PK/FK",
                    ha="center",
                    va="bottom",
                    fontsize=38,
                    rotation=90,
                )

        group_width = len(bars) * bar_width
        group_centers.append(group_start + (group_width - bar_width) / 2)
        group_start += group_width + group_gap

    ax.set_xticks(group_centers, [spec["label"] for spec in groups])
    ax.set_ylabel(ylabel)
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.tick_params(axis="x", pad=10)
    ax.tick_params(axis="y", pad=10)
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)
    # Pin the x-extent so every variant's panel has the same data range and
    # therefore the same display-pixels-per-bar at fixed figsize.
    ax.set_xlim(-bar_width, REFERENCE_PANEL_X_EXTENT)


def render_variant(variant):
    groups = build_groups(variant)
    # Skip operator groups for which neither bar has any data — keeps the
    # plot from showing an empty Filter pair if a competitor lacks that row.
    groups = [
        spec
        for spec in groups
        if any(
            not np.isnan(pick_value(q_name, bar_key, "prover time (s)"))
            for bar_key, q_name in spec["bars"]
        )
    ]
    if not groups:
        print(f"plot_micro: no data for variant={variant['curve']}; skipping")
        return

    group_gap = variant.get("group_gap", GROUP_GAP)
    # Fixed figure width across variants so PDFs scale identically when viewed
    # at equal screen width; narrower variants just leave whitespace on the
    # sides (handled in draw_panel via set_xlim).
    fig, axes = plt.subplots(1, 3, figsize=(REFERENCE_FIGSIZE_WIDTH, 8))
    panels = [
        ("prover time (s)", "Prover Time (s)"),
        ("verifier time (ms)", "Verifier Time (ms)"),
        ("proof size (KB)", "Proof Size (KB)"),
    ]
    for ax, (col, ylabel) in zip(axes, panels):
        draw_panel(ax, groups, col, ylabel, group_gap=group_gap)

    legend_specs = [
        (variant["tt_bar"], variant["tt_label"]),
        (variant["competitor_bar"], variant["competitor_label"]),
    ]
    legend_handles = [
        plt.Rectangle(
            (0, 0),
            1,
            1,
            facecolor=palette[bar_key]["face"],
            edgecolor=palette[bar_key]["edge"],
            hatch=hatches[bar_key],
            linewidth=0.8,
        )
        for bar_key, _ in legend_specs
    ]
    legend_labels = [label for _, label in legend_specs]

    fig.legend(
        handles=legend_handles,
        labels=legend_labels,
        ncol=len(legend_labels),
        loc="lower center",
        bbox_to_anchor=(0.5, -0.02),
        handlelength=2.2,
        handleheight=1.4,
        borderpad=0.6,
        columnspacing=1.6,
    )

    fig.tight_layout(rect=[0, 0.10, 1, 1])
    out = figures_dir / variant["outfile"]
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"plot_micro: wrote {out.relative_to(base_dir.parent)}")


for variant in VARIANTS:
    render_variant(variant)
