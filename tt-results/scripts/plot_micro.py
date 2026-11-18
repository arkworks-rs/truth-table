"""Plot the micro benchmark (third-party-bench/src/micro.rs) from tidy/micro.csv.

Every proof system runs on BN254 over the same rows; CPU provers on one thread,
the zkVM on the GPU.

Outputs:
  figures/micro.pdf          prover time, verifier time and proof size per
                             query at the largest table size; a query a system
                             cannot express gets a red cross
  figures/micro_setup.pdf    setup time, proving and verifying key sizes, and
                             the data owner's commitment time and size against
                             table size (the commitment for the 1% filter's
                             four-column table)

Usage:
  python3 tt-results/scripts/plot_micro.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter, LogFormatterSciNotation, LogLocator, MaxNLocator

plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams.update(
    {
        "font.size": 26,
        "axes.labelsize": 26,
        "xtick.labelsize": 24,
        "ytick.labelsize": 24,
        "legend.fontsize": 24,
        "hatch.linewidth": 0.6,
    }
)

base_dir = Path(__file__).resolve().parent.parent
data_path = base_dir / "tidy" / "micro.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

ALL = {"PoSQL", "QEDB", "Poneglyph", "Poneglyph (data-independent)", "zkVM (GPU)", "zkVM (GPU, Groth16)"}
NO_QEDB = ALL - {"QEDB"}
# The queries in plot order, and the competitors that can express each one.
QUERIES = [
    ("Filter 0.1%", ALL),
    ("Filter 1%", ALL),
    ("Filter 10%", ALL),
    ("Aggregate", ALL),
    ("Range", ALL),
    ("IN list", ALL),
    ("Arithmetic", NO_QEDB),
    ("Group by", NO_QEDB),
    ("Join PK/FK", NO_QEDB),
    # The data-independent Poneglyph circuits prove only PK/FK joins.
    ("Join M:N", NO_QEDB - {"Poneglyph (data-independent)"}),
    ("Order by", NO_QEDB - {"PoSQL"}),
]

# (System in micro.csv, legend label, bar style, line colour)
SYSTEMS = [
    ("TT", "TruthTable", {"edgecolor": "#1f77b4", "facecolor": "#d7e6f5", "hatch": "/"}),
    ("PoSQL", "PoSQL", {"edgecolor": "#e31a1c", "facecolor": "#f9d6d6", "hatch": "x"}),
    ("QEDB", "QEDB", {"edgecolor": "#33a02c", "facecolor": "#d9efd6", "hatch": "\\"}),
    ("Poneglyph", "Poneglyph", {"edgecolor": "#ff7f0e", "facecolor": "#ffe8d4", "hatch": "o"}),
    (
        "Poneglyph (data-independent)",
        "Poneglyph, data-independent keys",
        {"edgecolor": "#b35806", "facecolor": "#fdb863", "hatch": "."},
    ),
    ("zkVM (GPU)", "zkVM (SP1, GPU)", {"edgecolor": "#6a3d9a", "facecolor": "#e2d6ef", "hatch": "-"}),
    (
        "zkVM (GPU, Groth16)",
        "zkVM (SP1, GPU, Groth16)",
        {"edgecolor": "#3f2366", "facecolor": "#a58cc9", "hatch": "+"},
    ),
]

BAR_PANELS = [
    ("prover time (s)", "Prover (s)"),
    ("verifier time (ms)", "Verifier (ms)"),
    ("proof size (KB)", "Proof (KB)"),
]
SETUP_PANELS = [
    ("setup time (s)", "Setup (s)"),
    ("pk size (KB)", "Proving key (KB)"),
    ("vk size (KB)", "Verifying key (KB)"),
    ("commit time (s)", "Commitment time (s)"),
    ("commitment size (KB)", "Commitment (KB)"),
]


class PlainMinorFormatter(LogFormatterSciNotation):
    """Matplotlib labels minor ticks only on an axis spanning under a decade;
    this keeps its choice of ticks but prints them like the major ones."""

    def __call__(self, y, pos=None):
        return f"{y:g}" if super().__call__(y, pos) else ""


def log_axis(ax):
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.yaxis.set_minor_formatter(PlainMinorFormatter(labelOnlyBase=False))
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)


df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("﻿") for c in df.columns]
numeric = ["table log size"] + [c for c in df.columns if "(" in c]
for col in numeric:
    df[col] = pd.to_numeric(df[col], errors="coerce")
# One thread on the CPU, the GPU for the zkVM; the baseline is not plotted.
df = df[(df["threads"].astype(str).isin(["1", "1.0", "gpu"])) & (df["System"] != "Baseline")]
systems = [s for s in SYSTEMS if s[0] in set(df["System"])]


def value(rows, system, query, col):
    sub = rows[(rows["System"] == system) & (rows["Q"] == query)][col].dropna()
    return float(sub.iloc[0]) if len(sub) else np.nan


def legend(fig, extra=()):
    handles = [plt.Rectangle((0, 0), 1, 1, linewidth=0.8, **style) for _, _, style in systems]
    labels = [label for _, label, _ in systems]
    for handle, label in extra:
        handles.append(handle)
        labels.append(label)
    fig.legend(handles, labels, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.0))


def bars():
    sizes = df[df["System"] == "TT"]["table log size"].dropna()
    if sizes.empty:
        print("plot_micro: no TruthTable rows; skipping micro.pdf")
        return
    log_size = int(sizes.max())
    rows = df[df["table log size"] == log_size]
    x = np.arange(len(QUERIES))
    width = 0.8 / len(systems)
    offsets = (np.arange(len(systems)) - (len(systems) - 1) / 2) * width
    fig, axes = plt.subplots(len(BAR_PANELS), 1, figsize=(26, 18), sharex=True)
    for ax, (col, ylabel) in zip(axes, BAR_PANELS):
        for offset, (system, _, style) in zip(offsets, systems):
            heights = [value(rows, system, q, col) for q, _ in QUERIES]
            ax.bar(x + offset, heights, width, linewidth=0.8, **style)
            if system == "TT":
                continue
            unsupported = [i for i, (_, s) in enumerate(QUERIES) if system not in s]
            ax.plot(
                x[unsupported] + offset,
                [0.08] * len(unsupported),
                "x",
                color="red",
                markersize=12,
                markeredgewidth=3,
                transform=ax.get_xaxis_transform(),
                clip_on=False,
            )
        ax.set_ylabel(ylabel)
        log_axis(ax)
        ax.set_xlim(-0.6, len(QUERIES) - 0.4)
    axes[-1].set_xticks(x, [q for q, _ in QUERIES], rotation=30, ha="right")
    cross = Line2D([], [], color="red", marker="x", linestyle="", markersize=14, markeredgewidth=3)
    legend(fig, [(cross, "Not supported")])
    fig.tight_layout(rect=[0, 0, 1, 0.9])
    out = figures_dir / "micro.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"plot_micro: wrote {out.relative_to(base_dir.parent)} (2^{log_size} rows)")


def lines(ax, rows, col):
    for system, _, style in systems:
        sub = rows[rows["System"] == system].dropna(subset=[col]).sort_values("table log size")
        if not sub.empty:
            ax.plot(
                sub["table log size"],
                sub[col],
                marker="o",
                color=style["edgecolor"],
                linewidth=2,
            )
    log_axis(ax)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_xlabel("Table size (log2 rows)")


def line_legend(fig):
    handles = [Line2D([], [], color=style["edgecolor"], marker="o", linewidth=2) for _, _, style in systems]
    fig.legend(handles, [label for _, label, _ in systems], ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.0))


def setup():
    # Setup and keys do not depend on the query; the commitment does, so it is
    # the 1% filter's table.
    rows = df[df["Q"] == "Filter 1%"]
    fig, axes = plt.subplots(1, len(SETUP_PANELS), figsize=(36, 8))
    for ax, (col, ylabel) in zip(axes, SETUP_PANELS):
        lines(ax, rows, col)
        ax.set_ylabel(ylabel)
    line_legend(fig)
    fig.tight_layout(rect=[0, 0, 1, 0.82])
    out = figures_dir / "micro_setup.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"plot_micro: wrote {out.relative_to(base_dir.parent)}")


bars()
setup()
