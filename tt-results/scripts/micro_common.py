"""Shared data loading and styling for the micro-benchmark figures.

Every system keeps one colour and one marker in every figure. The hues are the
categorical palette in fixed order (blue, orange, aqua, yellow, magenta),
checked for colour-blind separation; a variant of a system (Poneglyph's
faithful circuits, the zkVM's Groth16 wrap) keeps its system's hue and is
dashed. Yellow, aqua and magenta are under 3:1 against white, so every line
also carries a marker and a direct label.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter, LogFormatterSciNotation, LogLocator

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "tidy" / "micro.csv"
FIGURES_DIR = BASE_DIR / "figures"

INK = "#1f1f1e"
MUTED_INK = "#5f5e5a"
GRID = "#d9d8d3"


class System:
    def __init__(self, key, label, color, marker, dashed=False):
        self.key = key
        self.label = label
        self.color = color
        self.marker = marker
        self.dashed = dashed

    @property
    def linestyle(self):
        return (0, (5, 3)) if self.dashed else "-"

    @property
    def bar_style(self):
        return {
            "edgecolor": self.color,
            "facecolor": self.color + "40",
            "hatch": "//" if self.dashed else None,
        }


# The order is the plot and legend order; `key` is the System in micro.csv.
SYSTEMS = [
    System("TT", "TruthTable", "#2a78d6", "o"),
    System("PoSQL", "PoSQL", "#eb6834", "s"),
    System("QEDB", "QEDB", "#1baf7a", "^"),
    System("Poneglyph (data-independent)", "Poneglyph, data-independent", "#eda100", "D"),
    System("Poneglyph", "Poneglyph, faithful", "#eda100", "D", dashed=True),
    System("zkVM (GPU)", "zkVM (SP1, GPU)", "#e87ba4", "v"),
    System("zkVM (GPU, Groth16)", "zkVM (SP1, GPU, Groth16)", "#e87ba4", "v", dashed=True),
]


_ALL = {"PoSQL", "QEDB", "Poneglyph", "Poneglyph (data-independent)", "zkVM (GPU)", "zkVM (GPU, Groth16)"}
_NO_QEDB = _ALL - {"QEDB"}
# The queries in plot order, and the competitors that can express each one
# (TruthTable runs all of them).
QUERIES = [
    ("Filter 0.1%", _ALL),
    ("Filter 1%", _ALL),
    ("Filter 10%", _ALL),
    ("Aggregate", _ALL),
    ("Range", _ALL),
    ("IN list", _ALL),
    ("Arithmetic", _NO_QEDB),
    ("Group by", _NO_QEDB),
    ("Join PK/FK", _NO_QEDB),
    # The data-independent Poneglyph circuits prove only PK/FK joins.
    ("Join M:N", _NO_QEDB - {"Poneglyph (data-independent)"}),
    ("Order by", _NO_QEDB - {"PoSQL"}),
]


def supports(system, query):
    return system.key == "TT" or system.key in dict(QUERIES)[query]


def style():
    plt.style.use("default")
    plt.rcParams.update(
        {
            "font.size": 24,
            "axes.labelsize": 24,
            "xtick.labelsize": 22,
            "ytick.labelsize": 22,
            "legend.fontsize": 21,
            "text.color": INK,
            "axes.labelcolor": INK,
            "axes.edgecolor": MUTED_INK,
            "xtick.color": MUTED_INK,
            "ytick.color": MUTED_INK,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "pdf.fonttype": 42,
        }
    )


def load():
    """micro.csv without the baseline: CPU systems on one thread, the zkVM on
    the GPU."""
    df = pd.read_csv(DATA_PATH)
    df.columns = [c.strip().lstrip("﻿") for c in df.columns]
    for col in ["table log size"] + [c for c in df.columns if "(" in c]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    threads = df["threads"].astype(str)
    return df[threads.isin(["1", "1.0", "gpu"]) & (df["System"] != "Baseline")]


def present(df):
    return [s for s in SYSTEMS if s.key in set(df["System"])]


class PlainMinorFormatter(LogFormatterSciNotation):
    """Matplotlib labels minor ticks only on an axis spanning under a decade;
    this keeps its choice of ticks but prints them like the major ones."""

    def __call__(self, y, pos=None):
        return f"{y:g}" if super().__call__(y, pos) else ""


def log_y(ax):
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.yaxis.set_minor_formatter(PlainMinorFormatter(labelOnlyBase=False))
    ax.grid(True, which="major", axis="y", color=GRID, linewidth=1)
    ax.set_axisbelow(True)


def rows_x(ax, pows):
    ax.set_xticks(pows, [f"$2^{{{p}}}$" for p in pows])
    ax.set_xlabel("Table rows")


def lines(ax, df, col, label_ends=True, systems=None):
    """One line per system of `col` against the table size; returns the
    systems drawn."""
    drawn, ends = [], []
    for s in systems or present(df):
        sub = df[df["System"] == s.key].dropna(subset=[col]).sort_values("table log size")
        if sub.empty:
            continue
        x, y = sub["table log size"].to_numpy(), sub[col].to_numpy()
        ax.plot(
            x,
            y,
            color=s.color,
            linestyle=s.linestyle,
            linewidth=2,
            marker=s.marker,
            markersize=9,
            markeredgecolor="white",
            markeredgewidth=1.2,
        )
        drawn.append(s)
        ends.append((x[-1], y[-1], s.label))
    if label_ends:
        direct_labels(ax, ends)
    return drawn


def direct_labels(ax, ends, min_gap=0.075):
    """Labels each line at its last point, nudged apart in log space (min_gap
    is in decades per axis height)."""
    if not ends:
        return
    lo, hi = (np.log10(v) for v in ax.get_ylim())
    gap = min_gap * (hi - lo)
    placed = []
    for x, y, label in sorted(ends, key=lambda e: e[1]):
        ly = np.log10(y)
        if placed and ly - placed[-1] < gap:
            ly = placed[-1] + gap
        placed.append(ly)
        ax.annotate(
            label,
            xy=(x, y),
            xytext=(x + 0.12, 10**ly),
            textcoords="data",
            va="center",
            ha="left",
            fontsize=20,
            color=INK,
            annotation_clip=False,
        )


def handles(systems):
    from matplotlib.lines import Line2D

    return [
        Line2D([], [], color=s.color, linestyle=s.linestyle, linewidth=2, marker=s.marker, markersize=9,
               markeredgecolor="white")
        for s in systems
    ]


def legend(fig, systems, ncol=4):
    fig.legend(
        handles(systems),
        [s.label for s in systems],
        ncol=ncol,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.0),
        frameon=False,
    )


def save(fig, name):
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = FIGURES_DIR / name
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out.relative_to(BASE_DIR.parent)}")
    return out
