"""Prover time against table size for the paper: eight micro queries (no 0.1%
or 1% filter, no aggregate) in rows of 3, 3 and 2 panels, with the legend in
the ninth cell.

Drawn at the paper's full text width with print-size type (paper_style.py).

Output:
  figures/micro_prover_paper.pdf

Usage:
  python3 tt-results/scripts/plot_micro_prover_paper.py
"""

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter, LogLocator

import micro_common as mc
import paper_style

HEIGHT_IN = 4.6
# (query in micro.csv, panel title)
QUERIES = [
    ("Filter 10%", "Filter"),
    ("Range", "Range"),
    ("IN list", "IN list"),
    ("Arithmetic", "Arithmetic"),
    ("Group by", "Group by"),
    ("Join PK/FK", "Join PK/FK"),
    ("Join M:N", "Join Many-to-Many"),
    ("Order by", "Order by"),
]
COL = "prover time (s)"

paper_style.apply(mc.INK, mc.MUTED_INK)

df = mc.load()
# Markers for the paper: TruthTable a star; the Groth16 wrap solid, told apart
# from the compressed proof by its circle.
MARKERS = {"TT": "*", "zkVM (GPU, Groth16)": "o"}
systems = [
    mc.System(s.key, s.label, s.color, MARKERS.get(s.key, s.marker))
    if s.key in MARKERS
    else s
    for s in mc.present(df)
]


def marker_size(marker):
    """Stars and triangles read smaller than other markers at the same size."""
    return {"*": 9, "^": 6.5, "v": 6.5}.get(marker, 5.5)


pows = sorted(int(p) for p in df["table log size"].dropna().unique())
supported = dict(mc.QUERIES)

fig, axes = plt.subplots(3, 3, figsize=(paper_style.WIDTH_IN, HEIGHT_IN), sharex=True, sharey=True)
for i, (ax, (query, title)) in enumerate(zip(axes.flat, QUERIES)):
    rows = df[df["Q"] == query]
    # TruthTable on top; the zkVM, whose lines cross the others, at the bottom.
    for s in reversed(systems):
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
            markersize=marker_size(s.marker),
            markeredgecolor="white",
            markeredgewidth=0 if s.marker == "*" else 0.6,
        )
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.grid(True, which="major", axis="y", color=mc.GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    # Row counts as 32K..1M: a superscript exponent would fall under 8 pt.
    ax.set_xticks(pows, [f"{2**p // 2**20}M" if p >= 20 else f"{2**p // 2**10}K" for p in pows])
    ax.set_xlim(pows[0] - 0.3, pows[-1] + 0.3)
    ax.set_title(title, pad=2)
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
            fontsize=paper_style.SIZE,
            color=mc.MUTED_INK,
            linespacing=1.1,
        )

legend_ax = axes.flat[-1]
legend_ax.axis("off")
legend_ax.legend(
    [
        Line2D([], [], color=s.color, linestyle=s.linestyle, linewidth=1.1, marker=s.marker,
               markersize=marker_size(s.marker), markeredgecolor="white",
               markeredgewidth=0 if s.marker == "*" else 0.6)
        for s in systems
    ],
    [s.label for s in systems],
    loc="center",
    frameon=False,
    handlelength=2.4,
)
fig.tight_layout(pad=0.1, h_pad=0.5, w_pad=0.6)
out = mc.FIGURES_DIR / "micro_prover_paper.pdf"
fig.savefig(out)
plt.close(fig)
print(f"wrote {out.relative_to(mc.BASE_DIR.parent)} ({paper_style.WIDTH_IN:.2f} x {HEIGHT_IN:.2f} in)")
