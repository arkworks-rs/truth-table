#!/usr/bin/env python3
"""Plot what a wider committed rule buys and costs: the prover's speed-up
and the proof-size factor per selectivity
regime, and the data owner's commit time and oracle size, all against the
number of bins committed.

Usage:
    python3 scripts/plot_widths.py \
        --shapes results/shapes-l_comment.csv \
        --commits results/commits-l_comment.csv \
        --measured results/proofs-l_comment.csv \
        -o results/widths-l_comment.png

- Prover speed-up: from `tt-fp-opt sweep --shapes` (the cost model, every
  query choosing its bins as the prover does), mean no-filter cost over
  mean cost per regime, as in plot_sweep.py. `--measured` overlays the
  measured speed-ups of the proved queries.
- Proof size: the fitted proof-size model below applied to the same
  shapes, mean size over mean no-filter size per regime.
- Commit: `tt-fp-measure commit` rows (`bins,commit_s,oracle_bytes,
  bins_bytes`, repeated per run), the median run over the no-fingerprint
  commit (`bins` 0). Older files with a `mode` column keep only `--mode`
  rows.
"""

import argparse
import csv
from collections import defaultdict
from statistics import median

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FixedLocator, NullLocator  # noqa: E402

SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3df"
SERIES = ["#0072B2", "#D55E00", "#009E73", "#E69F00", "#CC79A7", "#56B4E9"]
LABELS = ["<1%", "1–20%", "20–40%", "40–60%", "60–80%", "80–100%"]
TICKS = [16, 32, 64, 128, 256, 512, 1024, 2048]

# Proof size in bytes, fitted by least squares to 30 measured l_comment
# proofs at 2048 bins (leave-one-out error 4.2% mean, 13.5% max): a base per
# factor and literal character, and a fixed cost when the pre-filter runs.
# The bins opened (their commitments and Merkle siblings) add less than the
# scatter, so the fit has no per-bin term.
SIZE_BASE, SIZE_FACTOR, SIZE_CHAR, SIZE_PREFILTER = 18081, 2772, 689, 5149


def proof_size(factors, literal_len, limbs):
    return (SIZE_BASE + SIZE_FACTOR * factors + SIZE_CHAR * literal_len
            + SIZE_PREFILTER * (limbs > 0))


def read_shapes(path, lo):
    """Per regime and width: mean modeled cost, no-filter cost, proof size
    and no-filter proof size."""
    acc = defaultdict(lambda: [0.0, 0.0, 0.0, 0.0, 0])
    lines = csv.reader(open(path))
    header = next(lines)
    for fields in lines:
        # The pattern may hold commas: two fields before it, eight after.
        fields = fields[:2] + [",".join(fields[2:-8])] + fields[-8:]
        r = dict(zip(header, fields))
        bins = int(r["bins"])
        if bins < lo:
            continue
        n, lit, limbs = int(r["factors"]), int(r["literal_len"]), int(r["limbs"])
        a = acc[(int(r["regime"]), bins)]
        a[0] += float(r["cost_s"])
        a[1] += float(r["none_s"])
        a[2] += proof_size(n, lit, limbs)
        a[3] += proof_size(n, lit, 0)
        a[4] += 1
    return acc


def read_measured(path):
    """Measured speed-up per (regime, bins): mean baseline over mean time."""
    base, at = defaultdict(list), defaultdict(list)
    for r in csv.DictReader(open(path)):
        if r["status"] != "ok":
            continue
        key = int(r["regime"])
        if r["mode"] == "none":
            base[r["pattern"]] = float(r["prove_s"])
        else:
            at[(r["mode"], key, int(r["bins"]))].append((r["pattern"], float(r["prove_s"])))
    out = {}
    for (mode, regime, bins), rows in at.items():
        ref = sum(base[p] for p, _ in rows)
        out[(mode, regime, bins)] = ref / sum(t for _, t in rows)
    return out


def read_commits(path, mode):
    runs = defaultdict(list)
    size = {}
    for r in csv.DictReader(open(path)):
        bins = int(r["bins"])
        if r.get("mode", mode) != mode and bins != 0:
            continue
        runs[bins].append(float(r["commit_s"]))
        size[bins] = int(r["oracle_bytes"])
    t = {b: median(v) for b, v in runs.items()}
    xs = sorted(b for b in t if b > 0)
    return xs, [t[b] / t[0] for b in xs], [size[b] / size[0] for b in xs], t, size


def style(ax, xs):
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.set_xscale("log", base=2)
    ax.xaxis.set_major_locator(FixedLocator(xs))
    ax.xaxis.set_minor_locator(NullLocator())
    ax.set_xticklabels([str(x) for x in xs])
    ax.set_xlim(xs[0] / 1.25, xs[-1] * 1.25)
    ax.set_xlabel("bins in the committed rule")
    ax.axhline(1.0, color=TEXT_2, linewidth=1, linestyle=":")
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:g}×")
    ax.yaxis.set_minor_formatter(lambda v, _: "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="single",
                    help="the rows of older files that name a mode")
    ap.add_argument("--shapes", required=True)
    ap.add_argument("--commits", required=True)
    ap.add_argument("--measured")
    ap.add_argument("--column", default="l_comment")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    plt.rcParams.update({"font.size": 11, "axes.edgecolor": GRID,
                         "axes.labelcolor": TEXT_2, "xtick.color": TEXT_2,
                         "ytick.color": TEXT_2, "text.color": TEXT})
    shapes = read_shapes(args.shapes, TICKS[0])
    measured = read_measured(args.measured) if args.measured else {}
    fig, axes = plt.subplots(1, 3, figsize=(16, 5.2), facecolor=SURFACE)
    prover, size, commit = axes

    for regime, label in enumerate(LABELS):
        xs = sorted(b for r, b in shapes if r == regime)
        if not xs:
            continue
        a = [shapes[(regime, b)] for b in xs]
        color = SERIES[regime]
        prover.plot(xs, [x[1] / x[0] for x in a], color=color, linewidth=2, label=label)
        size.plot(xs, [x[2] / x[3] for x in a], color=color, linewidth=2, label=label)
        pts = sorted((b, s) for (m, r, b), s in measured.items()
                     if m == args.mode and r == regime)
        if len(pts) > 1:
            prover.plot([b for b, _ in pts], [s for _, s in pts], "o", color=color,
                        markersize=7, markerfacecolor=SURFACE, markeredgewidth=1.8)
    for ax in (prover, size):
        style(ax, TICKS)
    prover.set_yscale("log")
    prover.set_title("prover speed-up", color=TEXT, fontsize=12)
    prover.set_ylabel("ratio over no pre-filter")
    size.set_title("proof size", color=TEXT, fontsize=12)
    handles, labels = prover.get_legend_handles_labels()
    if measured:
        handles.append(plt.Line2D([], [], color=TEXT_2, marker="o", linestyle="",
                                  markerfacecolor=SURFACE, markeredgewidth=1.8))
        labels.append("measured (2 queries)")
    prover.legend(handles, labels, title="rows matched", frameon=False, fontsize=9,
                  title_fontsize=9, loc="upper left")

    xs, t, s, secs, sizes = read_commits(args.commits, args.mode)
    style(commit, xs)
    commit.plot(xs, t, color=TEXT, linewidth=2, marker="o", markersize=6,
                markeredgecolor=SURFACE, label="commit time")
    commit.plot(xs, s, color=TEXT_2, linewidth=2, linestyle="--", marker="s",
                markersize=6, markeredgecolor=SURFACE, label="oracle size")
    commit.set_yscale("log")
    commit.set_title("commit (data owner)", color=TEXT, fontsize=12)
    commit.legend(frameon=False, fontsize=9, loc="upper left")
    commit.annotate(f"{secs[0]:.2f} s, {sizes[0] / 1024:.1f} KB with no fingerprints",
                    (0.98, 0.03), xycoords="axes fraction", ha="right",
                    color=TEXT_2, fontsize=9)

    fig.suptitle(f"Committed width on {args.column}",
                 color=TEXT, fontsize=13)
    fig.text(0.5, -0.04,
             "Prover speed-up and proof size are modeled over the whole workload, "
             "every query choosing its bins as the prover does; proof size from a "
             "model fitted to 30 measured proofs. "
             + ("Circles: measured speed-ups of two proved queries per regime "
                "(proved before the model was refitted, so with its earlier limb "
                "choices). " if measured else "")
             + "Commit time (rules, encoding, commitment and Merkle roots, "
             "not the key load) and the verifier's oracle size are measured, medians of "
             "three commits of the 2^19-row table. Ratios over no pre-filter or no "
             "fingerprints; logarithmic axes except proof size.",
             ha="center", color=TEXT_2, fontsize=9, wrap=True)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150, bbox_inches="tight", facecolor=SURFACE)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
