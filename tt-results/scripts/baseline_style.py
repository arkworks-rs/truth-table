"""The no-proof baseline in the figures: its bar style and its TPC-H rows.

The baseline sends the columns a query reads and the verifier runs the query
itself (third-party-bench/src/baseline.rs). Its proofs are megabytes and its
prover milliseconds, so a panel that plots it next to TruthTable's prover time
or proof size needs a log axis.

Plain execution is the same query on the full tables with no verifiability at
all; it appears only in prover-time panels.
"""

from pathlib import Path

import pandas as pd

TIDY_DIR = Path(__file__).resolve().parent.parent / "tidy"

LABEL = "Baseline (no proof)"
EDGE = "#7f7f7f"
FACE = "#e5e5e5"
HATCH = ".."
BAR_STYLE = dict(facecolor=FACE, edgecolor=EDGE, hatch=HATCH, linewidth=0.8)


def _read(name):
    path = TIDY_DIR / name
    if not path.exists():
        print(f"baseline: {path} missing; the figure has no baseline bars")
        return None
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    for col in df.columns:
        if col not in ("Q", "variant", "table"):
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def tpch(variant, scale_factor):
    """Rows of tidy/tpch_baseline.csv for `variant` (`tt` or `pgn`) at
    `scale_factor`, indexed by query number."""
    df = _read("tpch_baseline.csv")
    if df is None:
        return pd.DataFrame()
    df = df[(df["variant"] == variant) & (df["scale-factor"] == scale_factor)].copy()
    df.index = df["Q"].str.strip().str.lower().str.lstrip("q").astype(int)
    return df


def commit(scale_factor):
    """Rows of tidy/commit_baseline.csv at `scale_factor`, indexed by table."""
    df = _read("commit_baseline.csv")
    if df is None:
        return pd.DataFrame()
    df = df[df["scale-factor"] == scale_factor].copy()
    df.index = df["table"].str.strip().str.lower()
    return df


def value(df, key, column):
    """`df[column]` at `key`, or NaN when the baseline has no such row."""
    if df.empty or key not in df.index:
        return float("nan")
    return float(df.loc[key, column])


EXEC_LABEL = "Plain execution (no verification)"
EXEC_BAR_STYLE = dict(facecolor="#f5e6c4", edgecolor="#b8860b", hatch="--", linewidth=0.8)
