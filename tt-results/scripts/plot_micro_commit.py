"""The data owner's commitment against table size, from tidy/micro.csv: its
time and its size.

The commitment depends on the table, not the query, so the figures use one
table every system commits: the four-column table of the 1% filter
(`filter_1` in third-party-bench/src/micro.rs).

Outputs:
  figures/micro_commit_time.pdf
  figures/micro_commit_size.pdf

Usage:
  python3 tt-results/scripts/plot_micro_commit.py
"""

import matplotlib.pyplot as plt

import micro_common as mc

QUERY = "Filter 1%"
# The zkVM's commitment is the data owner's hash on the CPU, the same for
# both proof modes, so it is drawn once.
SYSTEMS = [
    mc.System(s.key, "zkVM (SP1)", s.color, s.marker) if s.key == "zkVM (GPU)" else s
    for s in mc.SYSTEMS
    if s.key != "zkVM (GPU, Groth16)"
]
FIGURES = [
    ("commit time (s)", "Commitment time (s)", "micro_commit_time.pdf"),
    ("commitment size (KB)", "Commitment size (KB)", "micro_commit_size.pdf"),
]

mc.style()
rows = mc.load()
rows = rows[rows["Q"] == QUERY]
pows = sorted(int(p) for p in rows["table log size"].dropna().unique())
for col, ylabel, name in FIGURES:
    fig, ax = plt.subplots(figsize=(12, 8))
    mc.log_y(ax)
    mc.rows_x(ax, pows)
    ax.set_xlim(pows[0] - 0.25, pows[-1] + 0.25)
    ax.set_ylabel(ylabel)
    drawn = mc.lines(ax, rows, col, systems=[s for s in SYSTEMS if s.key in set(rows["System"])])
    mc.legend(fig, drawn, ncol=3)
    fig.tight_layout(rect=[0, 0, 1, 0.92])
    mc.save(fig, name)
