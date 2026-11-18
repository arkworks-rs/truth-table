"""TruthTable on TPC-H at scale factor 0.1, one thread: per-table commit time,
and per query the verifier time, prover time and proof size.

Drawn at the paper's full text width with print-size type (paper_style.py).

Reads:
  tidy/tpch.csv    — TPC-H prover/verifier/proof-size rows (System=tt)
  tidy/commit.csv  — per-table commit latency

Output:
  figures/tpch_tt_combined.pdf

Layout:
  ┌──────────────────┬──────────────────┐
  │  Commit latency  │  Verifier time   │
  │  (per table)     │                  │
  ├──────────────────┼──────────────────┤
  │  Prover time     │  Proof size      │
  └──────────────────┴──────────────────┘

Usage:
  python3 tt-results/scripts/plot_tt_tpch_combined.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter, LogLocator

import micro_common as mc
import paper_style

SCALE_FACTOR = 0.1
HEIGHT_IN = 2.6
# Commit-axis span above the tallest bar, as a factor, for the table key.
KEY_HEADROOM = 60
COLORS = plt.get_cmap("tab10").colors
# (colour index, hatch) of each panel.
COMMIT, VERIFIER, PROVER, PROOF = (1, "\\\\"), (2, "//"), (0, "//"), (4, "xx")
TABLE_KEYS = {
    "customer": "C",
    "lineitem": "L",
    "nation": "N",
    "orders": "O",
    "part": "P",
    "partsupp": "PS",
    "region": "R",
    "supplier": "S",
}

base_dir = Path(__file__).resolve().parent.parent
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

tdf = pd.read_csv(base_dir / "tidy" / "tpch.csv")
tdf.columns = [c.strip().lstrip("﻿") for c in tdf.columns]
tdf["Q"] = tdf["Q"].str.strip().str.lower()
tdf["System"] = tdf["System"].str.strip().str.lower()
tdf["scale-factor"] = pd.to_numeric(tdf["scale-factor"], errors="coerce")
tdf = tdf[(tdf["System"] == "tt") & (tdf["scale-factor"] == SCALE_FACTOR)].copy()
tdf.index = tdf["Q"].str.lstrip("q").astype(int)
tdf = tdf.sort_index()

cdf = pd.read_csv(base_dir / "tidy" / "commit.csv")
cdf.columns = [c.strip().lstrip("﻿") for c in cdf.columns]
cdf["table"] = cdf["table"].astype(str).str.strip().str.lower()
cdf["scale-factor"] = pd.to_numeric(cdf["scale-factor"], errors="coerce")
cdf = cdf[cdf["scale-factor"] == SCALE_FACTOR].sort_values("table").reset_index(drop=True)
if cdf.empty:
    raise RuntimeError(f"no commit rows with scale-factor={SCALE_FACTOR}")


def bar_style(panel, width):
    color, hatch = COLORS[panel[0]], panel[1]
    return dict(
        width=width,
        facecolor=tuple(0.85 + 0.15 * c for c in color),
        edgecolor=color,
        hatch=hatch,
        linewidth=0.8,
    )


def style_axis(ax, ylabel, log):
    ax.set_ylabel(ylabel)
    if log:
        ax.set_yscale("log")
        ax.yaxis.set_major_locator(LogLocator(base=10))
        ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.margins(x=0.01)


def query_panel(ax, panel, col, ylabel):
    x = np.arange(len(tdf))
    ax.bar(x, pd.to_numeric(tdf[col], errors="coerce"), **bar_style(panel, 0.6))
    ax.set_xticks(x, [str(q) for q in tdf.index])
    ax.set_xlabel("TPC-H Query")
    style_axis(ax, ylabel, log=False)


paper_style.apply(mc.INK, mc.MUTED_INK, base="seaborn-v0_8-whitegrid")
plt.rcParams.update(
    {
        "axes.spines.top": True,
        "axes.spines.right": True,
        "axes.edgecolor": "0.8",
        "grid.color": "0.9",
        "grid.linewidth": 0.6,
        "hatch.linewidth": 0.6,
    }
)
fig, ((commit_ax, verifier_ax), (prover_ax, proof_ax)) = plt.subplots(
    2, 2, figsize=(paper_style.WIDTH_IN, HEIGHT_IN)
)

ax = commit_ax
x = np.arange(len(cdf))
seconds = pd.to_numeric(cdf["latency-1thread(ms)"], errors="coerce") / 1000.0
ax.bar(x, seconds, **bar_style(COMMIT, 0.55))
ax.set_xticks(x, [TABLE_KEYS[t] for t in cdf["table"]])
ax.set_xlabel("Table")
style_axis(ax, "Commit Latency (s)", log=True)
# Head room above the tallest bar for the key, with no ticks in it.
lo, hi = seconds.min() / 2, seconds.max() * 2
ax.set_ylim(lo, hi * KEY_HEADROOM)
ax.set_yticks([t for t in 10.0 ** np.arange(-3, 4) if lo <= t <= hi])
ax.legend(
    [Patch(visible=False)] * len(TABLE_KEYS),
    [f"{k}: {t}" for t, k in TABLE_KEYS.items()],
    ncol=4,
    loc="upper center",
    handlelength=0,
    handletextpad=0,
    columnspacing=0.8,
    labelspacing=0.15,
    borderpad=0.3,
    borderaxespad=0.3,
    frameon=True,
    fancybox=False,
    edgecolor="0.8",
    framealpha=1,
)

query_panel(verifier_ax, VERIFIER, "total verifier time (ms)", "Verifier Time (ms)")
query_panel(prover_ax, PROVER, "prover time 1thread (s)", "Prover Time (s)")
query_panel(proof_ax, PROOF, "total proof size (KB)", "Proof Size (KB)")

fig.tight_layout(pad=0.1, h_pad=0.5, w_pad=0.8)
out = figures_dir / "tpch_tt_combined.pdf"
fig.savefig(out)
plt.close(fig)
print(f"wrote {out.relative_to(base_dir.parent)} ({paper_style.WIDTH_IN:.2f} x {HEIGHT_IN:.2f} in)")
