#!/usr/bin/env python3
"""Plot measured proving time against the cost model, from
`tt-fp-opt fit --predictions`.

Usage:
    python3 scripts/plot_validation.py results/predictions.csv -o results/validation.png

Each point is one real proof. The model value is leave-one-out: the prediction
of a model fitted without that point.
"""

import argparse
import csv
import math

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3df"
POINT = "#2a78d6"  # categorical slot 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("predictions")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.predictions)))
    measured = [float(r["measured_s"]) for r in rows]
    held_out = [float(r["held_out_s"]) for r in rows]
    rms = math.sqrt(sum((h - m) ** 2 for h, m in zip(held_out, measured)) / len(rows))
    top = max(measured + held_out) * 1.05

    plt.rcParams.update(
        {
            "font.size": 10,
            "axes.edgecolor": GRID,
            "axes.labelcolor": TEXT_2,
            "xtick.color": TEXT_2,
            "ytick.color": TEXT_2,
            "text.color": TEXT,
        }
    )
    fig, ax = plt.subplots(figsize=(6.4, 6), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.plot([0, top], [0, top], color=TEXT_2, linewidth=1, linestyle="--", label="model = measured")
    ax.plot(measured, held_out, "o", color=POINT, markersize=8, markeredgecolor=SURFACE,
            markeredgewidth=2, label=f"proofs (n = {len(rows)})")
    ax.set_xlim(0, top)
    ax.set_ylim(0, top)
    ax.set_xlabel("measured proving time (s)")
    ax.set_ylabel("leave-one-out model (s)")
    ax.set_title(f"Cost model vs real proofs — RMS error {rms:.1f} s", color=TEXT, fontsize=11)
    ax.legend(frameon=False, loc="upper left")
    fig.tight_layout()
    fig.savefig(args.out, dpi=150, facecolor=SURFACE)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
