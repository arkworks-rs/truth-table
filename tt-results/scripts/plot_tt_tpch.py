"""Plot prover / verifier / proof-size figures for TruthTable on the
regular TPC-H queries (System=tt rows of tidy/tpch.csv), next to the no-proof
baseline on the same `_tt` queries (tidy/tpch_baseline.csv) and the SP1 zkVM
on its GPU prover, with and without the Groth16 wrap (tidy/tpch_zkvm.csv).
The prover figure also has plain execution: the query on the full tables,
unverified.

Outputs:
  figures/tpch_tt_prover.pdf
  figures/tpch_tt_verifier.pdf
  figures/tpch_tt_proof_size.pdf

Usage:
  python3 tt-results/scripts/plot_tt_tpch.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter, LogLocator

import baseline_style

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

# Scale factor to plot. 0.05 and 0.1 are the only SFs with 4-thread numbers
# for every query.
SCALE_FACTOR = 0.1

# Full TPC-H query range. Queries with no `tt` row are rendered as a red cross
# at the bar position instead of a bar.
QUERY_IDS = list(range(1, 23))

# Matches the other standalone figures (plot_pgn.py / plot_micro.py): 46 in wide
# × 8 in tall is what 38 pt text needs to fit 22 query labels and the legend.
FIGSIZE = (46, 8)

base_dir = Path(__file__).resolve().parent.parent
data_path = base_dir / "tidy" / "tpch.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("﻿") for c in df.columns]
df["Q"] = df["Q"].str.strip().str.lower()
df["System"] = df["System"].str.strip().str.lower()
df["scale-factor"] = pd.to_numeric(df["scale-factor"], errors="coerce")
for col in [
    "prover time 1thread (s)",
    "prover time 4threads (s)",
    "total verifier time (ms)",
    "core verifier time (ms)",
    "preprocessed veritifier time (ms)",
    "total proof size (KB)",
]:
    df[col] = pd.to_numeric(df[col], errors="coerce")

df = df[(df["System"] == "tt") & (df["scale-factor"] == SCALE_FACTOR)].copy()

query_labels = [f"Q{q}" for q in QUERY_IDS]

baseline = baseline_style.tpch("tt", SCALE_FACTOR)


def baseline_values(col):
    return [baseline_style.value(baseline, q, col) for q in QUERY_IDS]


zkvm = {mode: baseline_style.zkvm_tpch("tt", SCALE_FACTOR, mode) for mode in ("compressed", "groth16")}


def zkvm_values(mode, col):
    return [baseline_style.value(zkvm[mode], q, col) for q in QUERY_IDS]


def _log_axis(ax, values):
    """Log y axis from below the smallest bar to above the largest, with room
    for the legend lines."""
    arr = np.asarray(values, dtype=float)
    ax.set_yscale("log")
    ax.set_ylim(np.nanmin(arr) / 2, np.nanmax(arr) * 3)
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))


def lookup(q_num, col):
    row = df[df["Q"] == f"q{q_num}"]
    if row.empty:
        return float("nan")
    return float(row[col].iloc[0])


def values(col):
    return [lookup(q, col) for q in QUERY_IDS]


def _style_axes(ax):
    ax.set_xlabel("TPC-H Query")
    ax.tick_params(axis="x", pad=8)
    ax.tick_params(axis="y", pad=8)
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)


def _missing_indices():
    return [i for i, q in enumerate(QUERY_IDS) if df[df["Q"] == f"q{q}"].empty]


def _mark_missing(ax, x_positions):
    idx = _missing_indices()
    if not idx:
        return
    xs = [x_positions[i] for i in idx]
    trans = ax.get_xaxis_transform()
    ax.scatter(
        xs,
        [0.02] * len(xs),
        marker="X",
        s=200,
        color="red",
        linewidths=2.0,
        edgecolors="red",
        zorder=5,
        transform=trans,
        clip_on=False,
    )


def plot_prover():
    one_thread = values("prover time 1thread (s)")
    four_thread = values("prover time 4threads (s)")

    colors = plt.get_cmap("tab10").colors
    light = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]
    one_color_idx = 0
    four_color_idx = 2
    filled = lambda style: {**style, "facecolor": style["edgecolor"]}
    series = [
        ("TT, 1 thread", one_thread,
         dict(facecolor=light[one_color_idx], edgecolor=colors[one_color_idx], hatch="/",
              linewidth=0.8)),
        ("TT, 4 threads", four_thread,
         dict(facecolor=light[four_color_idx], edgecolor=colors[four_color_idx], hatch="x",
              linewidth=0.8)),
        (baseline_style.ZKVM_GPU_LABEL, zkvm_values("compressed", "prover time (s)"),
         baseline_style.ZKVM_GPU_BAR_STYLE),
        (baseline_style.ZKVM_G16_LABEL, zkvm_values("groth16", "prover time (s)"),
         baseline_style.ZKVM_G16_BAR_STYLE),
        (f"{baseline_style.LABEL}, 1 thread", baseline_values("prover time 1thread (s)"),
         baseline_style.BAR_STYLE),
        (f"{baseline_style.LABEL}, 4 threads", baseline_values("prover time 4threads (s)"),
         filled(baseline_style.BAR_STYLE)),
        (f"{baseline_style.EXEC_LABEL}, 1 thread", baseline_values("execution time 1thread (s)"),
         baseline_style.EXEC_BAR_STYLE),
        (f"{baseline_style.EXEC_LABEL}, 4 threads",
         baseline_values("execution time 4threads (s)"), filled(baseline_style.EXEC_BAR_STYLE)),
    ]

    n = len(series)
    bar_width = 0.11
    group_gap = 0.2
    x = np.arange(len(QUERY_IDS)) * (n * bar_width + group_gap)

    fig, ax = plt.subplots(figsize=FIGSIZE)
    for i, (label, heights, style) in enumerate(series):
        ax.bar(x + i * bar_width, heights, width=bar_width, label=label, **style)

    one_arr = np.asarray(one_thread, dtype=float)
    four_arr = np.asarray(four_thread, dtype=float)
    one_avg = float(np.nanmean(one_arr))
    one_max = float(np.nanmax(one_arr))
    four_avg = float(np.nanmean(four_arr))
    four_max = float(np.nanmax(four_arr))
    ax.axhline(one_avg, linestyle=":", linewidth=1.6, color=colors[one_color_idx],
               label=f"TT 1-thread avg = {one_avg:.1f} s")
    ax.axhline(one_max, linestyle="--", linewidth=1.6, color=colors[one_color_idx],
               label=f"TT 1-thread max = {one_max:.1f} s")
    ax.axhline(four_avg, linestyle=":", linewidth=1.6, color=colors[four_color_idx],
               label=f"TT 4-thread avg = {four_avg:.1f} s")
    ax.axhline(four_max, linestyle="--", linewidth=1.6, color=colors[four_color_idx],
               label=f"TT 4-thread max = {four_max:.1f} s")

    center = x + (n - 1) / 2 * bar_width
    ax.set_xticks(center)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Prover Time (s)")
    _style_axes(ax)
    _mark_missing(ax, center)
    ax.set_xlim(x[0] - bar_width, x[-1] + n * bar_width)
    _log_axis(ax, [v for _, heights, _ in series for v in heights])
    ax.legend(
        ncol=4,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.04),
        handlelength=2.2,
        handleheight=1.4,
        borderpad=0.6,
        columnspacing=1.6,
        labelspacing=0.6,
    )

    fig.tight_layout()
    fig.savefig(figures_dir / "tpch_tt_prover.pdf", bbox_inches="tight")
    plt.close(fig)


def plot_verifier():
    core = values("core verifier time (ms)")
    preprocessed = values("preprocessed veritifier time (ms)")
    base = baseline_values("verifier time 1thread (ms)")
    zk = zkvm_values("compressed", "verifier time (ms)")
    zk16 = zkvm_values("groth16", "verifier time (ms)")

    bar_width = 0.22
    x = np.arange(len(QUERY_IDS), dtype=float)

    fig, ax = plt.subplots(figsize=FIGSIZE)
    colors = plt.get_cmap("tab10").colors
    light = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]

    ax.bar(
        x,
        core,
        width=bar_width,
        facecolor=light[2],
        edgecolor=colors[2],
        hatch="/",
        linewidth=0.8,
        label="Cryptographic",
    )
    ax.bar(
        x,
        preprocessed,
        width=bar_width,
        bottom=core,
        facecolor=light[3],
        edgecolor=colors[3],
        hatch="\\",
        linewidth=0.8,
        label="Non-cryptographic",
    )
    ax.bar(x + bar_width, zk, width=bar_width, **baseline_style.ZKVM_GPU_BAR_STYLE)
    ax.bar(x + 2 * bar_width, zk16, width=bar_width, **baseline_style.ZKVM_G16_BAR_STYLE)
    ax.bar(x + 3 * bar_width, base, width=bar_width, **baseline_style.BAR_STYLE)

    core_arr = np.asarray(core, dtype=float)
    pre_arr = np.asarray(preprocessed, dtype=float)
    full_arr = core_arr + pre_arr
    crypto_avg = float(np.nanmean(core_arr))
    crypto_max = float(np.nanmax(core_arr))
    full_avg = float(np.nanmean(full_arr))
    full_max = float(np.nanmax(full_arr))
    crypto_color = colors[2]
    full_color = colors[3]
    line_crypto_avg = ax.axhline(crypto_avg, linestyle=":", linewidth=1.6, color=crypto_color)
    line_crypto_max = ax.axhline(crypto_max, linestyle="--", linewidth=1.6, color=crypto_color)
    line_full_avg = ax.axhline(full_avg, linestyle=":", linewidth=1.6, color=full_color)
    line_full_max = ax.axhline(full_max, linestyle="--", linewidth=1.6, color=full_color)

    ax.set_xticks(x + 1.5 * bar_width)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Verifier Time (ms)")
    _style_axes(ax)
    _mark_missing(ax, x + 1.5 * bar_width)
    ax.set_xlim(x[0] - 0.6, x[-1] + 0.6 + 3 * bar_width)
    ax.set_ylim(0, float(np.nanmax(np.asarray(list(full_arr) + base + zk + zk16, dtype=float))) * 1.10)
    legend_handles = [
        Patch(facecolor=light[2], edgecolor=colors[2], hatch="/", label="TT cryptographic"),
        Patch(facecolor=light[3], edgecolor=colors[3], hatch="\\", label="TT non-cryptographic"),
        Patch(label=baseline_style.ZKVM_GPU_LABEL, **baseline_style.ZKVM_GPU_BAR_STYLE),
        Patch(label=baseline_style.ZKVM_G16_LABEL, **baseline_style.ZKVM_G16_BAR_STYLE),
        Patch(label=f"{baseline_style.LABEL}, 1 thread", **baseline_style.BAR_STYLE),
        (line_crypto_avg, f"TT crypto avg = {crypto_avg:.1f} ms"),
        (line_crypto_max, f"TT crypto max = {crypto_max:.1f} ms"),
        (line_full_avg, f"TT full avg = {full_avg:.1f} ms"),
        (line_full_max, f"TT full max = {full_max:.1f} ms"),
    ]
    handles = [h if isinstance(h, Patch) else h[0] for h in legend_handles]
    labels = [h.get_label() if isinstance(h, Patch) else h[1] for h in legend_handles]
    ax.legend(
        handles,
        labels,
        ncol=4,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.04),
        handlelength=2.2,
        handleheight=1.4,
        borderpad=0.6,
        columnspacing=1.6,
        labelspacing=0.6,
    )

    fig.tight_layout()
    fig.savefig(figures_dir / "tpch_tt_verifier.pdf", bbox_inches="tight")
    plt.close(fig)


def plot_proof_size():
    sizes = values("total proof size (KB)")
    base = baseline_values("proof size (KB)")
    zk = zkvm_values("compressed", "proof size (KB)")
    zk16 = zkvm_values("groth16", "proof size (KB)")

    bar_width = 0.22
    x = np.arange(len(QUERY_IDS), dtype=float)

    fig, ax = plt.subplots(figsize=FIGSIZE)
    colors = plt.get_cmap("tab10").colors
    light = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]

    ax.bar(
        x,
        sizes,
        width=bar_width,
        facecolor=light[4],
        edgecolor=colors[4],
        hatch="x",
        linewidth=0.8,
        label="TruthTable",
    )
    ax.bar(x + bar_width, zk, width=bar_width, label=baseline_style.ZKVM_GPU_LABEL,
           **baseline_style.ZKVM_GPU_BAR_STYLE)
    ax.bar(x + 2 * bar_width, zk16, width=bar_width, label=baseline_style.ZKVM_G16_LABEL,
           **baseline_style.ZKVM_G16_BAR_STYLE)
    ax.bar(x + 3 * bar_width, base, width=bar_width, label=baseline_style.LABEL,
           **baseline_style.BAR_STYLE)

    sizes_arr = np.asarray(sizes, dtype=float)
    mean_val = float(np.nanmean(sizes_arr))
    max_val = float(np.nanmax(sizes_arr))
    ax.axhline(mean_val, linestyle=":", linewidth=1.6, color=colors[0], label=f"TT avg = {mean_val:.1f} KB")
    ax.axhline(max_val, linestyle=":", linewidth=1.6, color=colors[3], label=f"TT max = {max_val:.1f} KB")

    ax.set_xticks(x + 1.5 * bar_width)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Proof Size (KB)")
    _style_axes(ax)
    _mark_missing(ax, x + 1.5 * bar_width)
    ax.set_xlim(x[0] - 0.6, x[-1] + 0.6 + 3 * bar_width)
    _log_axis(ax, sizes + base + zk + zk16)
    ax.legend(
        ncol=4,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.02),
        handlelength=2.2,
        borderpad=0.6,
        columnspacing=1.6,
    )

    fig.tight_layout()
    fig.savefig(figures_dir / "tpch_tt_proof_size.pdf", bbox_inches="tight")
    plt.close(fig)


plot_prover()
plot_verifier()
plot_proof_size()
