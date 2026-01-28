# TruthTable CLI (`tt`)

Run from the repo root:

```bash
cargo run --release -p exec --bin tt -- <command> [args]
```

If you have the binary installed on your PATH, you can replace the `cargo run`
prefix with `tt`.

## Command Overview

- `setup` - generate proving/verifying keys. 
- `data-gen` - generate TPC-H Parquet data (for testing and benchmarking purposes).
- `query` - run a SQL query against Parquet files. 
- `commit` - generate a table oracle from one Parquet file. 
- `prove` - generate a proof for a query. 
- `verify` - verify a proof. 

Notes:
- For `prove` and `verify`, the number and order of `--parquet-path` values must
  match the number and order of `--oracle` values.
- Add `--timed` to any command to print execution timing.
- Use `--help` on `tt` or any subcommand (e.g. `tt prove --help`) to see full
  usage and option details.

## Step-by-Step Benchmark Scenario (TPC-H)

This example runs a TPC-H query over the benchmark dataset using a single table
(`lineitem`) and query 1.

0) Prepare a folder for the artifacts
```bash
mkdir artifacts
```

1) Generate benchmark data:

```bash
tt -- data-gen --bench --output-dir artifacts
```

2) Generate keys sized for benchmark runs:

```bash
tt -- setup --size bench --pk-path artifacts/tt.pk --vk-path artifacts/tt.vk
```

3) Commit the `lineitem` table to an oracle:

```bash
tt -- commit \
  --parquet-path tpch-data/bench-data/lineitem.parquet \
  --pk-path tt_pk_20.pk \
  --output-path oracles/lineitem.oracle
```

4) Prove TPC-H query 1:

```bash
tt -- prove \
  --tpch-query 1 \
  --parquet-path artifacts/lineitem.parquet \
  --oracle artifacts/lineitem.oracle \
  --pk-path artifacts/tt.pk \
  --output-path artifacts/pi.proof \
  --timed
```

5) Verify the proof:

```bash
tt -- verify \
  --tpch-query 1 \
  --parquet-path artifacts/lineitem.parquet \
  --oracle artifacts/lineitem.oracle \
  --proof artifacts/pi.proof \
  --vk-path artifacts/tt.vk \
  --timed
```

For multi-table queries, pass each table's Parquet file and its matching oracle
in the same order to both `prove` and `verify`.
