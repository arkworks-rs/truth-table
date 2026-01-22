from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import LogFormatterMathtext, LogLocator

plt.style.use("seaborn-v0_8-whitegrid")

base_dir = Path(__file__).resolve().parent.parent
data_path = base_dir / "tidy" / "micro.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

# Load CSV
df = pd.read_csv(data_path)

# Ensure sorting by query number
df = df.sort_values(by=["Q", "System"])

# Extract unique queries and systems
queries = sorted(df["Q"].unique())
systems = sorted(df["System"].unique())

# Bar layout
x = np.arange(len(queries))
bar_width = 0.8 / len(systems)

# Plot
plt.figure(figsize=(7, 4))

for i, system in enumerate(systems):
    sys_df = df[df["System"] == system]
    heights = [
        sys_df[sys_df["Q"] == q]["prover time (s)"].values[0]
        for q in queries
    ]
    plt.bar(
        x + i * bar_width,
        heights,
        width=bar_width,
        label=system,
        alpha=0.9,
    )

# Axes and labels
plt.xticks(x + bar_width * (len(systems) - 1) / 2, queries)
plt.xlabel("Micro Benchmark")
plt.ylabel("Prover Time (s)")
plt.yscale("log")
plt.gca().yaxis.set_major_locator(LogLocator(base=10, subs=(1.0,)))
plt.gca().yaxis.set_major_formatter(LogFormatterMathtext(base=10))
plt.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)

# Legend
plt.legend()

# Tight layout for paper
plt.tight_layout()

# Save for LaTeX / paper
plt.savefig(figures_dir / "micro_prover_time.pdf")

plt.show()
