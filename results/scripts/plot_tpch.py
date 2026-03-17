from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

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
data_path = base_dir / "tidy" / "tpch.csv"
figures_dir = base_dir / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

# Load CSV and normalize column names (handles UTF-8 BOM in header).
df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("\ufeff") for c in df.columns]
df["Q"] = df["Q"].str.strip().str.lower()
df["System"] = df["System"].str.strip().str.lower()
df["scale-factor"] = pd.to_numeric(df["scale-factor"], errors="coerce")
for col in [
    "prover time 1thread (s)",
    "total verifier time (ms)",
    "core verifier time (ms)",
    "total proof size (KB)",
    "proof size core(KB)",
]:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# Only plot scale factor 0.04.
df = df[df["scale-factor"] == 0.04].copy()

# Queries to show, in order.
query_ids = [1, 5, 8, 9, 18]
query_labels = [f"Q{q}" for q in query_ids]

series_specs = [
    ("TT full", "tt", lambda q: f"q{q}"),
    ("TT simplified", "tt", lambda q: f"q{q}_p"),
    ("Poneglyph simplified", "poneglyph", lambda q: f"q{q}"),
]


def metric_column(system: str, value_key: str) -> str:
    if value_key == "prover":
        return "prover time 1thread (s)"
    if value_key == "verifier":
        return "total verifier time (ms)" if system == "poneglyph" else "core verifier time (ms)"
    if value_key == "proof_size":
        return "total proof size (KB)" if system == "poneglyph" else "proof size core(KB)"
    raise ValueError(f"Unknown metric key: {value_key}")


def pick_value(q_name: str, system: str, value_key: str) -> float:
    row = df[(df["Q"] == q_name) & (df["System"] == system)]
    if row.empty:
        return np.nan
    return float(row[metric_column(system, value_key)].iloc[0])


def build_series(value_key: str) -> list[list[float]]:
    return [
        [pick_value(q_name_fn(q), system, value_key) for q in query_ids]
        for _, system, q_name_fn in series_specs
    ]


def plot_metric(value_key: str, ylabel: str, output_name: str) -> None:
    series = build_series(value_key)

    group_gap = 0.18
    bar_width = 0.16
    group_width = 3 * bar_width + group_gap
    x = np.arange(len(query_ids)) * group_width

    fig, ax = plt.subplots(figsize=(10, 5.2))
    colors = plt.get_cmap("tab10").colors
    light_colors = [tuple(0.85 + 0.15 * c for c in color[:3]) for color in colors]
    hatches = ["/", "x", "\\"]
    legend_handles = []
    legend_labels = []

    for i, ((label, _, _), heights) in enumerate(zip(series_specs, series)):
        ax.bar(
            x + i * bar_width,
            heights,
            width=bar_width,
            alpha=1.0,
            facecolor=light_colors[i],
            edgecolor=colors[i],
            hatch=hatches[i],
            linewidth=0.8,
        )
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

    ax.set_xticks(x + bar_width, query_labels)
    ax.set_xlabel("TPC-H Query")
    ax.set_ylabel(ylabel)
    ax.tick_params(axis="x", pad=10)
    ax.tick_params(axis="y", pad=10)
    ax.grid(True, which="major", axis="y", linestyle="--", linewidth=0.8, alpha=0.7)
    ax.legend(
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

    fig.tight_layout()
    fig.savefig(figures_dir / output_name)
    plt.close(fig)


plot_metric("prover", "Prover Time (s)", "tpch_prover.pdf")
plot_metric("verifier", "Verifier Time (ms)", "tpch_verifier.pdf")
plot_metric("proof_size", "Proof Size (KB)", "tpch_proof_size.pdf")
