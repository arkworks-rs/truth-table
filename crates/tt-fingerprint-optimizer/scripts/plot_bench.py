#!/usr/bin/env python3
"""Plot the measured single-threaded fingerprint benchmark: five square
figures, every point a real run (no cost model).

Usage:
    python3 scripts/plot_bench.py --commits results/bench-commits-l_comment.csv \
        --proofs results/bench-proofs-l_comment.csv \
        --queries results/bench-queries-l_comment.csv --out-dir results

Inputs (written by the benchmark driver, one proof or commit per row):
- commits: `bins,run,commit_s,oracle_bytes,bins_bytes`; bins 0 commits no
  fingerprints.
- proofs: `kind,width,k,regime,pattern,prove_s,verify_s,proof_bytes,
  result_rows`, kind `baseline` (no fingerprints committed, so no
  pre-filter), `forced` (2048 bins committed, the prover made to test the
  first k bins of its greedy chain) or `natural` (the prover's own choice
  at a committed width).
- queries: `regime,chain,natural,pattern`: each query's chain length and
  the prover's own choice at 2048 bins.

Figures:
1. prover speed-up over no pre-filter vs bins committed (the prover's own
   choice); at 2048 bins that is the forced run at its natural k;
2. commit slowdown over committing no fingerprints vs bins committed;
3.-5. prover speed-up, verifier speed-up and proof-size factor vs the bins
   the prover tests, at 2048 bins committed. A query whose chain is
   shorter than k tests all of its bins;
6. per regime: prover time, verifier time and proof size with the
   pre-filter over without it, and (with --survivors) the fraction of
   rows the pre-filter keeps, on one shared axis, vs the bins tested.
A line is the mean over a regime's queries (or a width's commit runs); the
band spans their minimum and maximum.
"""

import argparse
import csv
import os
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FixedLocator, NullLocator  # noqa: E402

SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3df"
# Okabe-Ito, in fixed order per regime.
SERIES = ["#0072B2", "#D55E00", "#009E73"]
LABELS = ["<1%", "1–25%", "25–50%"]
SIZE = (5.2, 5.2)
FORCED_K = [0, 1, 2, 3, 4, 6, 8]
# The trade-off figures' shared y range.
TRADEOFF_YLIM = (1e-4, 1.6)


def read_queries(path):
    return [dict(r, regime=int(r["regime"]), chain=int(r["chain"]),
                 natural=int(r["natural"])) for r in csv.DictReader(open(path))]


def read_proofs(path):
    runs = {}
    for r in csv.DictReader(open(path)):
        key = (r["kind"], r["width"], r["k"], r["pattern"])
        runs[key] = (float(r["prove_s"]), float(r["verify_s"]), int(r["proof_bytes"]))
    return runs


def forced_run(runs, q, k):
    """The run testing the first k bins at 2048 committed; k past the chain
    is the whole chain, and k = 0 is the baseline."""
    if k == 0:
        return runs.get(("baseline", "0", "0", q["pattern"]))
    return runs.get(("forced", "2048", str(min(k, q["chain"])), q["pattern"]))


def natural_run(runs, q, width):
    if width == 2048:
        return forced_run(runs, q, q["natural"])
    return runs.get(("natural", str(width), "-", q["pattern"]))


def style(ax, xs, xlabel, ylabel, log_x=True):
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    if log_x:
        ax.set_xscale("log", base=2)
        ax.set_xlim(xs[0] / 1.2, xs[-1] * 1.2)
    else:
        ax.set_xlim(xs[0] - 0.4, xs[-1] + 0.4)
    ax.xaxis.set_major_locator(FixedLocator(xs))
    ax.xaxis.set_minor_locator(NullLocator())
    ax.set_xticklabels([str(x) for x in xs])
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.axhline(1.0, color=TEXT_2, linewidth=1, linestyle=":")
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:g}×")
    ax.yaxis.set_minor_formatter(lambda v, _: "")


def log_y(ax, ticks=None):
    """Log y-axis labelled as plain ratios (setting the scale resets the
    formatters, so they are set after it)."""
    ax.set_yscale("log")
    if ticks:
        ax.yaxis.set_major_locator(FixedLocator(ticks))
        ax.yaxis.set_minor_locator(NullLocator())
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:g}×")
    ax.yaxis.set_minor_formatter(lambda v, _: "")


def band(ax, xs, samples, color, label, floor=None):
    """Mean line with a min–max band; x values with no sample are skipped.
    On a log axis `floor` is where a band reaching zero is cut off."""
    pts = [(x, s) for x, s in zip(xs, samples) if s]
    if not pts:
        return
    x = [p for p, _ in pts]
    mean = [sum(s) / len(s) for _, s in pts]
    lo = [min(s) if floor is None else max(min(s), floor) for _, s in pts]
    ax.fill_between(x, lo, [max(s) for _, s in pts],
                    color=color, alpha=0.18, linewidth=0)
    ax.plot(x, mean, color=color, linewidth=2, marker="o", markersize=5,
            markeredgecolor=SURFACE, label=label)


def figure(title):
    fig, ax = plt.subplots(figsize=SIZE, facecolor=SURFACE)
    ax.set_title(title, color=TEXT, fontsize=12)
    return fig, ax


def save(fig, ax, out, legend_title):
    ax.legend(title=legend_title, frameon=False, fontsize=9, title_fontsize=9,
              loc="best")
    fig.tight_layout()
    fig.savefig(out, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    print(f"wrote {out}")


def per_regime(ax, queries, xs, value):
    """One band per regime: `value(q, x)` for each of its queries."""
    for regime, (color, label) in enumerate(zip(SERIES, LABELS)):
        qs = [q for q in queries if q["regime"] == regime]
        samples = [[v for q in qs if (v := value(q, x)) is not None] for x in xs]
        band(ax, xs, samples, color, f"{label} ({len(qs)} queries)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--commits", required=True)
    ap.add_argument("--proofs", required=True)
    ap.add_argument("--queries", required=True)
    ap.add_argument("--survivors",
                    help="`pattern,k,rows,survivors,matches`: rows passing the first k "
                         "bins of each query's chain (tt-fp-calibrate --shape-only)")
    ap.add_argument("--column", default="l_comment")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": GRID,
                         "axes.labelcolor": TEXT_2, "xtick.color": TEXT_2,
                         "ytick.color": TEXT_2, "text.color": TEXT})
    queries = read_queries(args.queries)
    runs = read_proofs(args.proofs)
    out = lambda name: os.path.join(args.out_dir, f"{name}-{args.column}.png")  # noqa: E731

    def ratio(run, base, field, invert=True):
        if run is None or base is None:
            return None
        return base[field] / run[field] if invert else run[field] / base[field]

    def base(q):
        return forced_run(runs, q, 0)

    # 1. Prover speed-up vs bins committed.
    widths = [16, 64, 128, 256, 512, 1024, 2048]
    fig, ax = figure("Prover speed-up vs bins committed")
    per_regime(ax, queries, widths,
               lambda q, w: ratio(natural_run(runs, q, w), base(q), 0))
    style(ax, widths, "bins committed (the prover picks its own)",
          "speed-up over no pre-filter")
    log_y(ax, [1, 1.5, 2, 3, 5, 7, 10, 15])
    save(fig, ax, out("bench-prover-vs-committed"), "rows matched")

    # 2. Commit slowdown vs bins committed.
    commits = defaultdict(list)
    for r in csv.DictReader(open(args.commits)):
        commits[int(r["bins"])].append(float(r["commit_s"]))
    none = sum(commits[0]) / len(commits[0])
    cw = sorted(b for b in commits if b > 0)
    fig, ax = figure("Commit slowdown vs bins committed")
    band(ax, cw, [[t / none for t in commits[b]] for b in cw], "#0b0b0b",
         f"{len(commits[0])} runs per width")
    style(ax, cw, "bins committed", "commit time over no fingerprints")
    ax.annotate(f"no fingerprints: {none:.1f} s", (0.97, 0.08),
                xycoords="axes fraction", ha="right", color=TEXT_2, fontsize=9)
    save(fig, ax, out("bench-commit-vs-committed"), None)

    # 3.-5. Against the bins the prover tests, 2048 committed.
    ks = FORCED_K
    for name, title, field, invert, ylabel in [
        ("bench-prover-vs-tested", "Prover speed-up vs bins tested", 0, True,
         "speed-up over no pre-filter"),
        ("bench-verifier-vs-tested", "Verifier speed-up vs bins tested", 1, True,
         "speed-up over no pre-filter"),
        ("bench-proof-size-vs-tested", "Proof size vs bins tested", 2, False,
         "proof size over no pre-filter"),
    ]:
        fig, ax = figure(title)
        per_regime(ax, queries, ks,
                   lambda q, k, f=field, i=invert: ratio(forced_run(runs, q, k), base(q), f, i))
        style(ax, ks, "bins tested by the prover (2048 committed)", ylabel, log_x=False)
        if field == 0:
            log_y(ax, [1, 1.5, 2, 3, 5, 7, 10, 15])
        save(fig, ax, out(name), "rows matched")

    # 6. Per regime: the three costs with the pre-filter over without it, all
    #    on one y range so they compare. A pre-filter that leaves no row puts
    #    the survivors' band on the axis floor.
    survivors = {}
    if args.survivors:
        for r in csv.DictReader(open(args.survivors)):
            survivors[(r["pattern"], int(r["k"]))] = int(r["survivors"]) / int(r["rows"])

    def survivor_ratio(q, k):
        return 1.0 if k == 0 else survivors.get((q["pattern"], min(k, q["chain"])))

    for regime, (label, tag) in enumerate(zip(LABELS, ["under1pct", "1to25pct", "25to50pct"])):
        qs = [q for q in queries if q["regime"] == regime]
        fig, ax = figure(f"With vs without pre-filter, {label} of rows match")
        for field, color, name in [
            (0, "#0072B2", "prover time"),
            (1, "#D55E00", "verifier time"),
            (2, "#009E73", "proof size"),
        ]:
            samples = [[v for q in qs
                        if (v := ratio(forced_run(runs, q, k), base(q), field, False)) is not None]
                       for k in ks]
            band(ax, ks, samples, color, name)
        if survivors:
            samples = [[v for q in qs if (v := survivor_ratio(q, k)) is not None] for k in ks]
            band(ax, ks, samples, "#CC79A7", "rows surviving the pre-filter",
                 floor=TRADEOFF_YLIM[0])
        style(ax, ks, "bins tested by the prover (2048 committed)",
              "with pre-filter / without", log_x=False)
        log_y(ax, [0.0001, 0.001, 0.01, 0.1, 0.2, 0.5, 1, 1.4])
        ax.set_ylim(TRADEOFF_YLIM)
        save(fig, ax, out(f"bench-tradeoff-{tag}"), f"{len(qs)} queries")

if __name__ == "__main__":
    main()
