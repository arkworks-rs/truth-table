"""Prover time, verifier time and proof size against table size, a panel per
micro query, from tidy/micro.csv. A system that cannot express a query is
named in its panel.

Outputs:
  figures/micro_prover_scaling.pdf
  figures/micro_verifier_scaling.pdf
  figures/micro_proof_size_scaling.pdf

Usage:
  python3 tt-results/scripts/plot_micro_scaling.py
"""

import matplotlib.pyplot as plt

import micro_common as mc

FIGURES = [
    ("prover time (s)", "Prover time (s)", "micro_prover_scaling.pdf"),
    ("verifier time (ms)", "Verifier time (ms)", "micro_verifier_scaling.pdf"),
    ("proof size (KB)", "Proof size (KB)", "micro_proof_size_scaling.pdf"),
]


def panels(df, col, ylabel, name):
    systems = mc.present(df)
    pows = sorted(int(p) for p in df["table log size"].dropna().unique())
    fig, axes = plt.subplots(3, 4, figsize=(30, 19), sharex=True, sharey=True)
    for i, (ax, (query, _)) in enumerate(zip(axes.flat, mc.QUERIES)):
        mc.log_y(ax)
        mc.lines(ax, df[df["Q"] == query], col, label_ends=False)
        ax.set_title(query, fontsize=24)
        mc.rows_x(ax, pows)
        ax.set_xlim(pows[0] - 0.25, pows[-1] + 0.25)
        # Only the panels with nothing below them label the table size.
        if i + 4 < len(mc.QUERIES):
            ax.set_xlabel("")
        else:
            ax.xaxis.set_tick_params(labelbottom=True)
        if i % 4 == 0:
            ax.set_ylabel(ylabel)
        missing = [s.label for s in systems if not mc.supports(s, query)]
        if missing:
            ax.text(
                0.97,
                0.04,
                "Not supported: " + ", ".join(missing),
                transform=ax.transAxes,
                ha="right",
                va="bottom",
                fontsize=17,
                color=mc.MUTED_INK,
            )
    legend_ax = axes.flat[-1]
    legend_ax.axis("off")
    legend_ax.legend(
        mc.handles(systems),
        [s.label for s in systems],
        loc="center",
        frameon=False,
        fontsize=24,
    )
    fig.tight_layout()
    mc.save(fig, name)


mc.style()
data = mc.load()
for col, ylabel, name in FIGURES:
    panels(data, col, ylabel, name)
