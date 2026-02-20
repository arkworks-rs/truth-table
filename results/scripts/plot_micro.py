from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import LogFormatterMathtext, LogLocator

plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams.update(
    {
        "font.size": 21,
        "axes.labelsize": 22,
        "xtick.labelsize": 20,
        "ytick.labelsize": 20,
        "legend.fontsize": 20,
        "hatch.linewidth": 0.6,
    }
)

base_dir = Path(__file__).resolve().parent.parent
data_path = base_dir / "tidy" / "micro.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

# Load CSV and normalize column names (handles UTF-8 BOM in header).
df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("\ufeff") for c in df.columns]
df = df[(df["Q"] != "Q") & (df["System"] != "System")]
df["table log size"] = pd.to_numeric(df["table log size"], errors="coerce")

def normalize_q(name: str) -> str:
    q = str(name).strip().lower()
    if q == "limit offset":
        return "limit"
    return q

df["q_norm"] = df["Q"].apply(normalize_q)
df["system_norm"] = df["System"].str.strip().str.lower()

# Fix to table log size 18 for all systems.
df = df[df["table log size"] == 18]

query_order = ["filter", "aggregate", "join", "limit"]
queries = [q for q in query_order if q in set(df["q_norm"])]
query_labels = [q.title() for q in queries]

systems = ["tt", "posql", "qedb"]
system_labels = ["TT", "PoSQL", "QEDB"]

def pick_time(q_name: str, system: str) -> float:
    row = df[(df["q_norm"] == q_name) & (df["system_norm"] == system)]
    if row.empty:
        return np.nan
    return float(row["prover time (s)"].values[0])

series = [[pick_time(q, system) for q in queries] for system in systems]

# Bar layout (groups with 3 bars each, tight spacing between groups).
group_gap = 0.18
bar_width = 0.16
group_width = 3 * bar_width + group_gap
x = np.arange(len(queries)) * group_width

plt.figure(figsize=(10, 5.2))
palette = {
    "tt": {"edge": "#1f77b4", "face": "#d7e6f5"},
    "posql": {"edge": "#e31a1c", "face": "#f9d6d6"},
    "qedb": {"edge": "#33a02c", "face": "#d9efd6"},
}
hatches = ["/", "x", "\\"]
legend_handles = []
legend_labels = []

for i, (system, label, heights) in enumerate(zip(systems, system_labels, series)):
    style = palette[system]
    plt.bar(
        x + i * bar_width,
        heights,
        width=bar_width,
        label=label,
        alpha=1.0,
        facecolor=style["face"],
        edgecolor=style["edge"],
        hatch=hatches[i],
        linewidth=0.8,
    )
    legend_handles.append(
        plt.Rectangle(
            (0, 0),
            1,
            1,
            facecolor=style["face"],
            edgecolor=style["edge"],
            hatch=hatches[i],
            linewidth=0.8,
        )
    )
    legend_labels.append(label)

# Axes and labels
plt.xticks(x + bar_width, query_labels)
plt.xlabel("Micro Benchmark")
plt.ylabel("Prover Time (s)")
ax = plt.gca()
ax.set_yscale("log")
ax.yaxis.set_major_locator(LogLocator(base=10))
ax.yaxis.set_major_formatter(LogFormatterMathtext(base=10))
plt.gca().tick_params(axis="x", pad=10)
plt.gca().tick_params(axis="y", pad=10)
plt.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)

# Legend
plt.legend(
    handles=legend_handles,
    labels=legend_labels,
    ncol=3,
    loc="upper center",
    bbox_to_anchor=(0.5, 1.32),
    handlelength=2.2,
    handleheight=1.4,
    borderpad=0.6,
    columnspacing=1.6,
)

# Tight layout for paper
plt.tight_layout()

# Save for LaTeX / paper
plt.savefig(figures_dir / "micro_prover_time.pdf")
