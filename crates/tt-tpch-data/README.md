# tpch-data

Utility crate for generating TPC-H tables as Parquet files and for printing canonical TPC-H SQL. The generated Parquet is preprocessed for dbSNARK experiments.

## Features

- Generates TPC-H tables via `tpchgen`/`tpchgen-arrow` and writes Parquet.
- Adds an `activator` boolean column to every table:
  - `true` for original rows, `false` for any appended rows.
- Pads each table to a power-of-two row count by duplicating the last row.
- Prints TPC-H query SQL using DuckDB's TPCH extension.
- Optionally prints DataFusion logical plans and Treeviz DOT for queries.

## Binaries

- `gen_test_data` — generate a small dataset (default scale 0.01).
- `gen_bench_data` — generate a dataset for benchmarking at a given scale.
- `run_tpch` — print TPC-H query SQL (and optionally DataFusion logical plan / Treeviz).

## Install & Build

This crate is part of the dbSNARK workspace. From the repo root:

```
cargo build -p tpch-data
```

DuckDB is pulled in with the `bundled` feature; no system install required.

## Data Generation

Both commands perform preprocessing before writing Parquet:
- Append `activator: bool` column.
- Set `activator=true` on original rows.
- Pad to power-of-two rows by duplicating the last row; set `activator=false` on appended rows.

Outputs are written under the workspace `artifacts/` directory by default.

### gen_test_data

```
cargo run -p tpch-data --bin gen_test_data [--scale 0.01] [--out-dir DIR]
```

Defaults:
- `--scale` = `0.01`
- `--out-dir` = `artifacts/test-data`

### gen_bench_data

```
cargo run -p tpch-data --bin gen_bench_data <scale> [--out-dir DIR]
```

Defaults:
- `--out-dir` = `artifacts/bench-data`

Tables emitted (one Parquet each):
`nation.parquet`, `region.parquet`, `part.parquet`, `supplier.parquet`, `partsupp.parquet`, `customer.parquet`, `orders.parquet`, `lineitem.parquet`.

## Query Printing

Use DuckDB's TPCH extension to print canonical SQL. No hardcoding required.

```
# Print a single query's SQL (e.g., Q7)
cargo run -p tpch-data --bin run_tpch 7

# Print all 22 queries' SQL
cargo run -p tpch-data --bin run_tpch all
```

### Logical Plan and Treeviz

You can also print DataFusion logical plans and Treeviz DOT. These require the Parquet data on disk.

```
# Single query: SQL + plan
cargo run -p tpch-data --bin run_tpch 7 --plan [--data-dir path/to/parquet]

# Single query: SQL + Treeviz (DOT)
cargo run -p tpch-data --bin run_tpch 7 --treeviz [--data-dir path/to/parquet]

# All queries: SQL + plan + Treeviz
cargo run -p tpch-data --bin run_tpch all --plan --treeviz [--data-dir path/to/parquet]
```

If `--data-dir` is omitted, the binaries look for `artifacts/test-data`, then `artifacts/bench-data`.

## Notes

- Parquet writing uses Apache Arrow + Parquet crates.
- Query SQL is sourced from DuckDB's `tpch_queries()` (installed/loaded automatically in-memory).
- DataFusion version: 46.x (for plan/treeviz printing).

## License

This crate depends on third-party packages under their respective licenses. See Cargo.toml for details.
