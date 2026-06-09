"""Plot prover / verifier / proof-size figures for TruthTable on the
regular TPC-H queries (System=tt rows of tidy/tpch.csv).

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

    bar_width = 0.38
    group_gap = 0.30
    group_width = 2 * bar_width + group_gap
    x = np.arange(len(QUERY_IDS)) * group_width

    fig, ax = plt.subplots(figsize=(18, 5.4))
    colors = plt.get_cmap("tab10").colors
    light = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]

    one_color_idx = 0
    four_color_idx = 2

    ax.bar(
        x,
        one_thread,
        width=bar_width,
        facecolor=light[one_color_idx],
        edgecolor=colors[one_color_idx],
        hatch="/",
        linewidth=0.8,
        label="1 thread",
    )
    ax.bar(
        x + bar_width,
        four_thread,
        width=bar_width,
        facecolor=light[four_color_idx],
        edgecolor=colors[four_color_idx],
        hatch="x",
        linewidth=0.8,
        label="4 threads",
    )

    one_arr = np.asarray(one_thread, dtype=float)
    four_arr = np.asarray(four_thread, dtype=float)
    one_avg = float(np.nanmean(one_arr))
    one_max = float(np.nanmax(one_arr))
    four_avg = float(np.nanmean(four_arr))
    four_max = float(np.nanmax(four_arr))
    ax.axhline(one_avg, linestyle=":", linewidth=1.6, color=colors[one_color_idx],
               label=f"1-thread avg = {one_avg:.1f} s")
    ax.axhline(one_max, linestyle="--", linewidth=1.6, color=colors[one_color_idx],
               label=f"1-thread max = {one_max:.1f} s")
    ax.axhline(four_avg, linestyle=":", linewidth=1.6, color=colors[four_color_idx],
               label=f"4-thread avg = {four_avg:.1f} s")
    ax.axhline(four_max, linestyle="--", linewidth=1.6, color=colors[four_color_idx],
               label=f"4-thread max = {four_max:.1f} s")

    ax.set_xticks(x + bar_width / 2)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Prover Time (s)")
    _style_axes(ax)
    _mark_missing(ax, x + bar_width / 2)
    ymax = max(one_max, four_max)
    ax.set_ylim(0, ymax * 1.18)
    ax.legend(
        ncol=3,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.04),
        handlelength=2.2,
        handleheight=1.4,
        borderpad=0.6,
        columnspacing=1.6,
        labelspacing=0.6,
    )

    fig.tight_layout()
    fig.savefig(figures_dir / "tpch_tt_prover.pdf")
    plt.close(fig)


def plot_verifier():
    core = values("core verifier time (ms)")
    preprocessed = values("preprocessed veritifier time (ms)")

    bar_width = 0.55
    x = np.arange(len(QUERY_IDS), dtype=float)

    fig, ax = plt.subplots(figsize=(18, 5.4))
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

    ax.set_xticks(x)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Verifier Time (ms)")
    _style_axes(ax)
    _mark_missing(ax, x)
    ax.set_ylim(0, full_max * 1.18)
    legend_handles = [
        Patch(facecolor=light[2], edgecolor=colors[2], hatch="/", label="Cryptographic"),
        Patch(facecolor=light[3], edgecolor=colors[3], hatch="\\", label="Non-cryptographic"),
        (line_crypto_avg, f"Crypto avg = {crypto_avg:.1f} ms"),
        (line_crypto_max, f"Crypto max = {crypto_max:.1f} ms"),
        (line_full_avg, f"Full avg = {full_avg:.1f} ms"),
        (line_full_max, f"Full max = {full_max:.1f} ms"),
    ]
    handles = [h if isinstance(h, Patch) else h[0] for h in legend_handles]
    labels = [h.get_label() if isinstance(h, Patch) else h[1] for h in legend_handles]
    ax.legend(
        handles,
        labels,
        ncol=3,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.04),
        handlelength=2.2,
        handleheight=1.4,
        borderpad=0.6,
        columnspacing=1.6,
        labelspacing=0.6,
    )

    fig.tight_layout()
    fig.savefig(figures_dir / "tpch_tt_verifier.pdf")
    plt.close(fig)


def plot_proof_size():
    sizes = values("total proof size (KB)")

    bar_width = 0.55
    x = np.arange(len(QUERY_IDS), dtype=float)

    fig, ax = plt.subplots(figsize=(18, 5.4))
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
    )

    sizes_arr = np.asarray(sizes, dtype=float)
    mean_val = float(np.nanmean(sizes_arr))
    max_val = float(np.nanmax(sizes_arr))
    ax.axhline(mean_val, linestyle=":", linewidth=1.6, color=colors[0], label=f"Avg = {mean_val:.1f} KB")
    ax.axhline(max_val, linestyle=":", linewidth=1.6, color=colors[3], label=f"Max = {max_val:.1f} KB")

    ax.set_xticks(x)
    ax.set_xticklabels(query_labels)
    ax.set_ylabel("Proof Size (KB)")
    _style_axes(ax)
    _mark_missing(ax, x)
    ax.legend(
        ncol=2,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.18),
        handlelength=2.2,
        borderpad=0.6,
        columnspacing=1.6,
    )

    fig.tight_layout()
    fig.savefig(figures_dir / "tpch_tt_proof_size.pdf")
    plt.close(fig)


plot_prover()
plot_verifier()
plot_proof_size()
