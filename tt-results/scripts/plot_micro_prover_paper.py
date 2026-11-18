"""Prover time against table size for the paper: eight micro queries (no 0.1%
or 1% filter, no aggregate) in rows of 3, 3 and 2 panels, with the legend in
the ninth cell.

The figure is drawn at the full text width of the IEEE S&P (IEEEtran
conference, compsoc) layout, 7.0 in, with print-size type, so it is included
at `width=\\textwidth` without scaling.

Output:
  figures/micro_prover_paper.pdf

Usage:
  python3 tt-results/scripts/plot_micro_prover_paper.py
"""

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter, LogLocator

import micro_common as mc

# \textwidth of \documentclass[conference,compsoc]{IEEEtran}: 505.89 pt.
WIDTH_IN = 505.89 / 72.27
HEIGHT_IN = 5.0
QUERIES = [
    "Filter 10%",
    "Range",
    "IN list",
    "Arithmetic",
    "Group by",
    "Join PK/FK",
    "Join M:N",
    "Order by",
]
COL = "prover time (s)"

plt.rcParams.update(
    {
        "font.size": 8,
        "axes.titlesize": 8,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7.5,
        "text.color": mc.INK,
        "axes.labelcolor": mc.INK,
        "axes.edgecolor": mc.MUTED_INK,
        "axes.linewidth": 0.6,
        "xtick.color": mc.MUTED_INK,
        "ytick.color": mc.MUTED_INK,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "pdf.fonttype": 42,
    }
)

df = mc.load()
systems = mc.present(df)
pows = sorted(int(p) for p in df["table log size"].dropna().unique())
supported = dict(mc.QUERIES)

fig, axes = plt.subplots(3, 3, figsize=(WIDTH_IN, HEIGHT_IN), sharex=True, sharey=True)
for i, (ax, query) in enumerate(zip(axes.flat, QUERIES)):
    rows = df[df["Q"] == query]
    for s in systems:
        sub = rows[rows["System"] == s.key].dropna(subset=[COL]).sort_values("table log size")
        if sub.empty:
            continue
        ax.plot(
            sub["table log size"],
            sub[COL],
            color=s.color,
            linestyle=s.linestyle,
            linewidth=1.1,
            marker=s.marker,
            markersize=3.5,
            markeredgecolor="white",
            markeredgewidth=0.5,
        )
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.grid(True, which="major", axis="y", color=mc.GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    ax.set_xticks(pows, [f"$2^{{{p}}}$" for p in pows])
    ax.set_xlim(pows[0] - 0.3, pows[-1] + 0.3)
    ax.set_title(query, pad=3)
    if i % 3 == 0:
        ax.set_ylabel("Prover time (s)")
    # The bottom panel of each column labels the table size.
    if i + 3 >= len(QUERIES):
        ax.xaxis.set_tick_params(labelbottom=True)
        ax.set_xlabel("Table rows")
    missing = [s.label for s in systems if s.key != "TT" and s.key not in supported[query]]
    if missing:
        ax.text(
            0.98,
            0.03,
            "Not supported:\n" + ", ".join(missing),
            transform=ax.transAxes,
            ha="right",
            va="bottom",
            fontsize=6,
            color=mc.MUTED_INK,
            linespacing=1.1,
        )

legend_ax = axes.flat[-1]
legend_ax.axis("off")
legend_ax.legend(
    [
        Line2D([], [], color=s.color, linestyle=s.linestyle, linewidth=1.1, marker=s.marker,
               markersize=4, markeredgecolor="white", markeredgewidth=0.5)
        for s in systems
    ],
    [s.label for s in systems],
    loc="center",
    frameon=False,
    handlelength=2.4,
)
fig.tight_layout(pad=0.3, h_pad=0.6, w_pad=0.6)
out = mc.FIGURES_DIR / "micro_prover_paper.pdf"
fig.savefig(out)
plt.close(fig)
print(f"wrote {out.relative_to(mc.BASE_DIR.parent)} ({WIDTH_IN:.2f} x {HEIGHT_IN:.2f} in)")
