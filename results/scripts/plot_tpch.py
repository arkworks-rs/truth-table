from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import LogFormatterMathtext, LogLocator

plt.style.use("seaborn-v0_8-whitegrid")

base_dir = Path(__file__).resolve().parent.parent
data_path = base_dir / "tidy" / "tpch.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

# Load CSV and normalize column names (handles UTF-8 BOM in header).
df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("\ufeff") for c in df.columns]

# Only plot scale factor 0.04
df = df[df["scale-factor"] == 0.04]

# Queries to show, in order.
query_ids = [1, 3, 5, 8, 9, 18]
query_labels = [f"Q{q}" for q in query_ids]

def pick_time(q_id: int, q_suffix: str, system: str) -> float:
    q_name = f"q{q_id}_{q_suffix}"
    row = df[(df["Q"] == q_name) & (df["System"] == system)]
    if row.empty:
        raise ValueError(f"Missing row for Q={q_name}, System={system}, scale=0.04")
    return float(row["prover time (s)"].values[0])

# Build grouped bar data: [unabridged tt, abridged tt, abridged poneglyph]
series_labels = ["TT unabridged", "TT abridged", "Poneglyph abridged"]
series = [
    [pick_time(q, "unabridged", "tt") for q in query_ids],
    [pick_time(q, "abridged", "tt") for q in query_ids],
    [pick_time(q, "abridged", "poneglyph") for q in query_ids],
]

# Bar layout (6 groups, 3 bars each, tight spacing between groups).
group_gap = 0.12
bar_width = 0.22
group_width = 3 * bar_width + group_gap
x = np.arange(len(query_ids)) * group_width

plt.figure(figsize=(10, 3.6))
colors = plt.get_cmap("tab10").colors  # seaborn-like categorical palette
light_colors = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]
hatches = ["//", "xx", "\\\\"]
legend_handles = []
legend_labels = []
for i, (label, heights) in enumerate(zip(series_labels, series)):
    bars = plt.bar(
        x + i * bar_width,
        heights,
        width=bar_width,
        label=label,
        alpha=1.0,
        facecolor=light_colors[i],
        edgecolor=colors[i],
        hatch=hatches[i],
        linewidth=0.8,
    )
    # Add a light tinted legend patch matching the series color.
    legend_handles.append(
        plt.Rectangle(
            (0, 0),
            1,
            1,
            facecolor=light_colors[i],
            edgecolor=colors[i],
            hatch=hatches[i],
            linewidth=0.8,
        )
    )
    legend_labels.append(label)

# Axes and labels
plt.xticks(x + bar_width, query_labels)
plt.xlabel("TPC-H Query")
plt.ylabel("Prover Time (s)")
plt.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)

# Legend
plt.legend(
    handles=legend_handles,
    labels=legend_labels,
    ncol=3,
    loc="upper center",
    bbox_to_anchor=(0.5, 1.18),
    handlelength=2.2,
    handleheight=1.4,
    borderpad=0.6,
    columnspacing=1.6,
)

plt.tight_layout()
plt.savefig(figures_dir / "prover_time_tpch_0p04.pdf")
