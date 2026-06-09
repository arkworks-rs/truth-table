"""Plot the micro-benchmark comparison (TruthTable / PoSQL / QEDB) on the
shared Filter / Aggregate / Join / Join PK/FK / Limit operators.

Reads tidy/micro.csv.

Output:
  figures/micro_combined.pdf — single PDF with prover time, verifier time,
                                and proof size side-by-side, sharing one legend.

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

# Fix to table log size 19. Pick the thread count present in the CSV (all rows
# share the same NUM_THREADS from run_micro.sh).
available_threads = sorted(df["threads"].dropna().unique())
if not available_threads:
    raise RuntimeError(f"no rows with a threads value in {data_path}")
threads_value = 1 if 1 in available_threads else int(available_threads[0])
df = df[(df["table log size"] == 19) & (df["threads"] == threads_value)].copy()
print(f"plot_micro: filtering to threads={threads_value}")

group_specs = [
    {
        "label": "Filter",
        "bars": [("tt", "filter"), ("posql", "filter"), ("qedb", "filter")],
    },
    {
        "label": "Aggregate",
        "bars": [("tt", "aggregate"), ("posql", "aggregate"), ("qedb", "aggregate")],
    },
    {
        "label": "Join",
        "bars": [
            ("tt", "join"),
            ("tt_join_pk_fk", "join_pk_fk"),
            ("posql", "join"),
            ("qedb", "join"),
        ],
    },
    {
        "label": "Limit",
        "bars": [("tt", "limit"), ("posql", "limit"), ("qedb", "limit")],
    },
]
groups = [
    spec
    for spec in group_specs
    if any(not df[df["q_norm"] == q_name].empty for _, q_name in spec["bars"])
]

palette = {
    "tt": {"edge": "#1f77b4", "face": "#d7e6f5"},
    "tt_join_pk_fk": {"edge": "#1f77b4", "face": "#d7e6f5"},
    "posql": {"edge": "#e31a1c", "face": "#f9d6d6"},
    "qedb": {"edge": "#33a02c", "face": "#d9efd6"},
}
hatches = {
    "tt": "/",
    "tt_join_pk_fk": "/",
    "posql": "x",
    "qedb": "\\",
}
legend_specs = [("tt", "TT"), ("posql", "PoSQL"), ("qedb", "QEDB")]


def pick_value(q_name, system, value_col):
    lookup_system = "tt" if system == "tt_join_pk_fk" else system
    row = df[(df["q_norm"] == q_name) & (df["system_norm"] == lookup_system)]
    if row.empty:
        return np.nan
    return float(row[value_col].iloc[0])


def draw_panel(ax, value_col, ylabel):
    group_gap = 0.22
    bar_width = 0.16
    group_centers = []
    group_start = 0.0

    for spec in groups:
        bars = spec["bars"]
        offsets = np.arange(len(bars)) * bar_width
        for offset, (system, q_name) in zip(offsets, bars):
            height = pick_value(q_name, system, value_col)
            x_pos = group_start + offset
            ax.bar(
                x_pos,
                height,
                width=bar_width,
                alpha=1.0,
                facecolor=palette[system]["face"],
                edgecolor=palette[system]["edge"],
                hatch=hatches[system],
                linewidth=0.8,
            )
            if system == "tt_join_pk_fk" and not np.isnan(height):
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


# Width chosen so each subplot's aspect ratio matches the original single-panel
# figsize (10, 5.2 → 1.92:1). With height 8, each subplot wants ~15.4 wide, so
# total width ≈ 46.
fig, axes = plt.subplots(1, 3, figsize=(46, 8))
panels = [
    ("prover time (s)", "Prover Time (s)"),
    ("verifier time (ms)", "Verifier Time (ms)"),
    ("proof size (KB)", "Proof Size (KB)"),
]
for ax, (col, ylabel) in zip(axes, panels):
    draw_panel(ax, col, ylabel)

# Single shared legend, centered below all three panels.
legend_handles = [
    plt.Rectangle(
        (0, 0),
        1,
        1,
        facecolor=palette[system]["face"],
        edgecolor=palette[system]["edge"],
        hatch=hatches[system],
        linewidth=0.8,
    )
    for system, _ in legend_specs
]
legend_labels = [label for _, label in legend_specs]

fig.legend(
    handles=legend_handles,
    labels=legend_labels,
    ncol=3,
    loc="lower center",
    bbox_to_anchor=(0.5, -0.02),
    handlelength=2.2,
    handleheight=1.4,
    borderpad=0.6,
    columnspacing=1.6,
)

# Reserve room at the bottom for the figure-level legend.
fig.tight_layout(rect=[0, 0.10, 1, 1])
fig.savefig(figures_dir / "micro_combined.pdf", bbox_inches="tight")
plt.close(fig)
