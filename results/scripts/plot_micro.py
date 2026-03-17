from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter, LogLocator

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


def normalize_q(name: str) -> str:
    q = str(name).strip().lower()
    if q == "limit offset":
        return "limit"
    if q in {"join pk/fk", "join pk fk"}:
        return "join_pk_fk"
    return q


# Load CSV and normalize column names (handles UTF-8 BOM in header).
df = pd.read_csv(data_path)
df.columns = [c.strip().lstrip("\ufeff") for c in df.columns]
df = df[(df["Q"] != "Q") & (df["System"] != "System")].copy()
df["table log size"] = pd.to_numeric(df["table log size"], errors="coerce")
df["threads"] = pd.to_numeric(df["threads"], errors="coerce")
df["prover time (s)"] = pd.to_numeric(df["prover time (s)"], errors="coerce")
df["verifier time (ms)"] = pd.to_numeric(df["verifier time (ms)"], errors="coerce")
df["proof size (KB)"] = pd.to_numeric(df["proof size (KB)"], errors="coerce")
df["q_norm"] = df["Q"].apply(normalize_q)
df["system_norm"] = df["System"].str.strip().str.lower()

# Fix to table log size 19 and single-threaded runs for all systems.
df = df[(df["table log size"] == 19) & (df["threads"] == 1)].copy()

group_specs = [
    {
        "label": "Filter",
        "bars": [("tt", "filter"), ("posql", "filter"), ("qedb", "filter")],
    },
    {
        "label": "Aggregate",
        "bars": [("tt", "aggregate"), ("posql", "aggregate"), ("qedb", "aggregate")],
    },
    {
        "label": "Join",
        "bars": [
            ("tt", "join"),
            ("tt_join_pk_fk", "join_pk_fk"),
            ("posql", "join"),
            ("qedb", "join"),
        ],
    },
    {
        "label": "Limit",
        "bars": [("tt", "limit"), ("posql", "limit"), ("qedb", "limit")],
    },
]
groups = [
    spec
    for spec in group_specs
    if any(not df[df["q_norm"] == q_name].empty for _, q_name in spec["bars"])
]

palette = {
    "tt": {"edge": "#1f77b4", "face": "#d7e6f5"},
    "tt_join_pk_fk": {"edge": "#1f77b4", "face": "#d7e6f5"},
    "posql": {"edge": "#e31a1c", "face": "#f9d6d6"},
    "qedb": {"edge": "#33a02c", "face": "#d9efd6"},
}
hatches = {
    "tt": "/",
    "tt_join_pk_fk": "/",
    "posql": "x",
    "qedb": "\\",
}
legend_specs = [("tt", "TT"), ("posql", "PoSQL"), ("qedb", "QEDB")]


def pick_value(q_name: str, system: str, value_col: str) -> float:
    lookup_system = "tt" if system == "tt_join_pk_fk" else system
    row = df[(df["q_norm"] == q_name) & (df["system_norm"] == lookup_system)]
    if row.empty:
        return np.nan
    return float(row[value_col].iloc[0])


def plot_metric(value_col: str, ylabel: str, output_name: str) -> None:
    fig, ax = plt.subplots(figsize=(10, 5.2))

    legend_handles = [
        plt.Rectangle(
            (0, 0),
            1,
            1,
            facecolor=palette[system]["face"],
            edgecolor=palette[system]["edge"],
            hatch=hatches[system],
            linewidth=0.8,
        )
        for system, _ in legend_specs
    ]
    legend_labels = [label for _, label in legend_specs]

    group_gap = 0.22
    bar_width = 0.16
    group_centers = []
    group_start = 0.0

    for spec in groups:
        bars = spec["bars"]
        offsets = np.arange(len(bars)) * bar_width
        for offset, (system, q_name) in zip(offsets, bars):
            height = pick_value(q_name, system, value_col)
            x_pos = group_start + offset
            ax.bar(
                x_pos,
                height,
                width=bar_width,
                alpha=1.0,
                facecolor=palette[system]["face"],
                edgecolor=palette[system]["edge"],
                hatch=hatches[system],
                linewidth=0.8,
            )
            if system == "tt_join_pk_fk" and not np.isnan(height):
                ax.text(
                    x_pos,
                    height * 1.18,
                    "* PK/FK",
                    ha="center",
                    va="bottom",
                    fontsize=13,
                    rotation=90,
                )

        group_width = len(bars) * bar_width
        group_centers.append(group_start + (group_width - bar_width) / 2)
        group_start += group_width + group_gap

    ax.set_xticks(group_centers, [spec["label"] for spec in groups])
    ax.set_xlabel("SQL Operator")
    ax.set_ylabel(ylabel)
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(LogLocator(base=10))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
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


plot_metric("prover time (s)", "Prover Time (s)", "micro_prover_time.pdf")
plot_metric("proof size (KB)", "Proof Size (KB)", "micro_proof_size.pdf")
plot_metric("verifier time (ms)", "Verifier Time (ms)", "micro_verifier_time.pdf")
