#!/usr/bin/env python3
"""Plot the prover's bin choice: the speed-up over no pre-filter after
testing the first k bins of each query's chain, the most selective first,
per selectivity regime (mean no-filter cost over mean cost, as in
plot_sweep.py).

Usage:
    python3 scripts/plot_chain.py results/chains-l_comment.csv \
        --bins 2048 -o results/chain-l_comment.png

The CSV comes from `tt-fp-opt sweep --chains ... --chains-at <bins>`. A
query with fewer candidate bins than k keeps its cost at all its bins
(there is nothing left to add). Each panel's y-axis is zoomed on the top
of its curve; points far below it are listed in the corner.
"""

import argparse
import csv
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3df"
SERIES = ["#0072B2", "#D55E00", "#009E73", "#E69F00", "#CC79A7", "#56B4E9"]
LABELS = ["<1%", "1–20%", "20–40%", "40–60%", "60–80%", "80–100%"]


def read(path, bins):
    chains = defaultdict(dict)
    regime, chosen = {}, {}
    for row in csv.DictReader(open(path)):
        if int(row["bins"]) != bins:
            continue
        q = int(row["query"])
        chains[q][int(row["limbs"])] = float(row["cost_s"])
        regime[q] = int(row["regime"])
        if row["chosen"] == "1":
            chosen[q] = int(row["limbs"])
    return {q: [c[k] for k in sorted(c)] for q, c in chains.items()}, regime, chosen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--bins", type=int, required=True)
    ap.add_argument("--max-limbs", type=int, default=16)
    ap.add_argument("--column", default="l_comment")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    chains, regime, chosen = read(args.path, args.bins)
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
    shown = [r for r in range(len(LABELS)) if any(regime[q] == r for q in chains)][:4]
    fig, axes = plt.subplots(2, 2, figsize=(12, 8), facecolor=SURFACE)
    for ax, r in zip(axes.flat, shown):
        qs = [q for q in chains if regime[q] == r]
        top = min(args.max_limbs, max(len(chains[q]) for q in qs) - 1)
        ks = list(range(top + 1))
        mean = [
            sum(chains[q][min(k, len(chains[q]) - 1)] for q in qs) / len(qs) for k in ks
        ]
        speedup = [mean[0] / m for m in mean]
        best = max(ks, key=lambda k: (speedup[k], -k))
        picked = sum(chosen[q] for q in qs) / len(qs)

        ax.set_facecolor(SURFACE)
        ax.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        color = SERIES[r]
        ax.plot(ks, speedup, color=color, linewidth=2, marker="o", markersize=5,
                markeredgecolor=SURFACE, markeredgewidth=1, zorder=3)
        # Zoom on the top of the curve: from a little under the lowest point
        # to its right to a little over the peak.
        right = min(speedup[best:])
        span = max(speedup[best] - right, 0.02 * speedup[best])
        lo, hi = right - 1.6 * span, speedup[best] + 0.6 * span
        ax.set_ylim(lo, hi)
        ax.set_xlim(-0.5, top + 0.5)
        ax.set_xticks(ks)
        off = [f"{k} bin{'s' * (k != 1)}: {speedup[k]:.2f}×" for k in ks if speedup[k] < lo]
        if off:
            ax.text(0.98, 0.04, "below the panel:\n" + "\n".join(off),
                    transform=ax.transAxes, ha="right", va="bottom", color=TEXT_2,
                    fontsize=9)
        ax.plot([best], [speedup[best]], "o", color=color, markersize=10,
                markeredgecolor=SURFACE, markeredgewidth=1.5, zorder=4)
        ax.annotate(f"peak: {speedup[best]:.2f}× at {best} bin{'s' * (best != 1)}",
                    (best, speedup[best]), xytext=(8, 8), textcoords="offset points",
                    color=TEXT_2, fontsize=10)
        ax.yaxis.set_major_formatter(lambda v, _: f"{v:g}×")
        ax.set_title(f"{LABELS[r]} of rows match  ({len(qs)} queries;"
                     f" prover picks {picked:.1f} bins on average)",
                     color=TEXT, fontsize=11)
        ax.set_xlabel("bins tested (most selective first)")
        ax.set_ylabel("speed-up over no pre-filter")
    for ax in list(axes.flat)[len(shown):]:
        ax.set_visible(False)
    fig.suptitle(f"The prover's bin choice on {args.column}, committed rule at "
                 f"{args.bins} bins", color=TEXT, fontsize=13)
    fig.text(0.5, -0.04,
             "Each step adds the bin whose test keeps the fewest rows. The speed-up "
             "grows while bins remove rows, then falls as each extra bin adds about "
             "0.05 s. A query with fewer bins keeps its last cost. Modeled; each "
             "panel's y-axis is zoomed on the top of its curve.",
             ha="center", color=TEXT_2, fontsize=9, wrap=True)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150, bbox_inches="tight", facecolor=SURFACE)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
