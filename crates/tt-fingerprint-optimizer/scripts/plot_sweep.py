#!/usr/bin/env python3
"""Plot a width sweep of the committed rule as the speed-up of every
selectivity regime over its cost with no pre-filter, one figure per sweep,
all on the same axes so the figures compare side by side.

Usage:
    python3 scripts/plot_sweep.py \
        --sweep single=results/sweep-single-l_comment.csv \
        --column l_comment -o results/sweep-{mode}-l_comment.png

Each CSV comes from `tt-fp-opt sweep` (every query choosing its own bins,
as the prover does). `{mode}` in the output path is replaced per figure.
"""

import argparse
import csv
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FixedFormatter, FixedLocator, NullLocator  # noqa: E402

SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3df"
# Every regime is a solid line, so hue alone separates them: the Okabe-Ito
# colors, as in plot_packing_regimes.py (adjacent pairs clear CVD dE 9.6).
SERIES = ["#0072B2", "#D55E00", "#009E73", "#E69F00", "#CC79A7", "#56B4E9"]

HOW = {
    "single": "the k most common features, one bin each",
}


def read(path):
    regimes = defaultdict(list)
    labels, sizes = {}, {}
    for row in csv.DictReader(open(path)):
        r = int(row["regime"])
        labels[r] = row["label"]
        sizes[r] = int(row["queries"])
        bins = int(row["bins"])
        # A rule may stop short of the width asked for (once every feature
        # has its own bin); repeated widths are one rule.
        if any(b == bins for b, _ in regimes[r]):
            continue
        speedup = float(row["no_filter_s"]) / float(row["cost_s"])
        regimes[r].append((bins, speedup))
    return {r: sorted(v) for r, v in regimes.items()}, labels, sizes


def plot(mode, data, ylim, xmax, column, workload, out):
    regimes, labels, sizes = data
    ticks = [t for t in (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048) if t <= xmax]

    fig, ax = plt.subplots(figsize=(11, 6.5), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.set_xscale("log", base=2)
    ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.xaxis.set_minor_locator(NullLocator())
    ax.set_xticklabels([str(t) for t in ticks])
    ax.set_xlim(1 / 1.3, xmax * 1.3)
    # Log so that the small gains of the unselective regimes stay readable
    # next to the large ones of the selective regimes.
    ax.set_yscale("log", base=2)
    yticks = [t for t in (1, 1.1, 1.25, 1.5, 2, 3, 4, 6, 8, 12, 16) if ylim[0] <= t <= ylim[1]]
    ax.yaxis.set_major_locator(FixedLocator(yticks))
    ax.yaxis.set_minor_locator(NullLocator())
    ax.yaxis.set_major_formatter(FixedFormatter([f"{t:g}×" for t in yticks]))
    ax.set_ylim(*ylim)

    ax.axhline(1.0, color=TEXT_2, linewidth=1, linestyle=(0, (2, 3)), zorder=1)
    ax.annotate("no pre-filter", (xmax * 1.3, 1.0), xytext=(-4, -13),
                textcoords="offset points", ha="right", color=TEXT_2, fontsize=10)

    for r in sorted(regimes):
        color = SERIES[r % len(SERIES)]
        xs = [b for b, _ in regimes[r]]
        ys = [s for _, s in regimes[r]]
        ax.plot(xs, ys, color=color, linewidth=2, zorder=2,
                label=f"{labels[r]}  ({sizes[r]} queries)")
        if xs[-1] < xmax:
            # Asking for more bins gives this same rule: carry it flat.
            ax.plot([xs[-1], xmax], [ys[-1], ys[-1]], color=color, linewidth=1.5,
                    linestyle=(0, (1, 2)), zorder=2)
        best = max(zip(xs, ys), key=lambda p: p[1])
        ax.plot([best[0]], [best[1]], "o", color=color, markersize=7,
                markeredgecolor=SURFACE, markeredgewidth=1.5, zorder=3)
        # Only peaks worth reading get a direct label; the flat regimes
        # would stack on top of each other near 1x.
        if best[1] > 1.1:
            ax.annotate(f"{best[1]:.2f}× at {best[0]} bins", best, xytext=(0, 11),
                        textcoords="offset points", ha="center", color=TEXT_2,
                        fontsize=10)
    widest = max(b for v in regimes.values() for b, _ in v)
    if widest < xmax:
        # The rule could not grow further: say so where its lines end.
        ax.axvline(widest, color=TEXT_2, linewidth=1, linestyle=(0, (1, 3)), zorder=1)
        ax.annotate(f"the rule stops at {widest} bins",
                    (widest, 0.55), xycoords=("data", "axes fraction"), xytext=(8, 0),
                    textcoords="offset points", ha="left", color=TEXT_2, fontsize=10)

    ax.set_ylabel("speed-up over no pre-filter")
    ax.set_xlabel("bins in the committed rule (k)")
    ax.set_title(f"Pre-filter speed-up per selectivity regime: {mode} rule",
                 color=TEXT, fontsize=13)
    legend = ax.legend(title="selectivity", frameon=False, fontsize=10,
                       loc="upper left", ncol=2)
    legend.get_title().set_color(TEXT_2)
    fig.text(0.5, -0.05,
             f"Cost model on {workload or f'the {column} workload'}; {HOW.get(mode, mode)}. "
             "Every query tests the subset of its bins the prover's greedy "
             "picks. Markers are each regime's best width; both axes are log "
             "scale, and all modes share the y-axis.",
             ha="center", color=TEXT_2, fontsize=9, wrap=True)
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
    print(f"wrote {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", action="append", required=True,
                    help="mode=path of a `tt-fp-opt sweep` CSV; repeatable")
    ap.add_argument("--column", default="l_comment")
    ap.add_argument("--workload", default="",
                    help="how the scoring workload was drawn, for the footnote")
    ap.add_argument("-o", "--out", required=True,
                    help="output path; {mode} is replaced by the mode")
    args = ap.parse_args()

    plt.rcParams.update(
        {
            "font.size": 11,
            "axes.edgecolor": GRID,
            "axes.labelcolor": TEXT_2,
            "xtick.color": TEXT_2,
            "ytick.color": TEXT_2,
            "text.color": TEXT,
        }
    )
    sweeps = {}
    for spec in args.sweep:
        mode, path = spec.split("=", 1)
        sweeps[mode] = read(path)
    speedups = [s for regimes, _, _ in sweeps.values() for v in regimes.values() for _, s in v]
    xmax = max(b for regimes, _, _ in sweeps.values() for v in regimes.values() for b, _ in v)
    # Shared range: a little below the lowest point, headroom for the top label.
    ylim = (min(0.9, min(speedups) * 0.93), max(speedups) * 1.18)
    for mode, data in sweeps.items():
        plot(mode, data, ylim, xmax, args.column, args.workload, args.out.replace("{mode}", mode))


if __name__ == "__main__":
    main()
