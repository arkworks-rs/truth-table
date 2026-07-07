---
title: Workspace Crates
description: The crates that make up the TruthTable workspace.
---

TruthTable is a Cargo workspace. The main crates are:

| Crate | Responsibility |
| --- | --- |
| `tt-core` | Core intermediate representation, prover, and verifier passes. |
| `tt-arithmetic` | Column/table encodings and arithmetization primitives. |
| `tt-front-end` | SQL front-end and query lowering. |
| `tt-proof-planner` | Turns logical plans into proof plans. |
| `tt-exec` | Execution and setup. |
| `tt-col-toolbox` | Column utilities. |
| `tt-tpch-data` | TPC-H data generation and loading. |

:::note
Benchmark-only crates (for comparison against other systems) are excluded from
the default workspace build and compiled explicitly when generating results.
:::

For full, up-to-date API documentation, build the Rust docs locally:

```sh
cargo doc --open
```
