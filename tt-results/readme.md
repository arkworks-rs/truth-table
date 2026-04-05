This folder contains the data and helper scripts to generate the plots.

Reproducible setup (macOS/Linux):
1) Install Python 3.12.x (recommend 3.12.8).
2) Create and activate a virtual environment.
3) Install dependencies.
4) Run the plotting script.

Example:
```bash
cd dbsnark-system/tt-results
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python tt-scripts/plot_tpch.py
```

Optional: if you use pyenv, this repo includes `.python-version` to pin Python.

Streamlit dashboard for bench JSONL:
```bash
cd /home/alrshir/truth-table/tt-results
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r dashboard_requirements.txt
streamlit run bench_dashboard.py
```

By default the dashboard reads:
`/home/alrshir/truth-table/tt-results/raw/bench_stats.jsonl`
