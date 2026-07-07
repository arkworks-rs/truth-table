---
title: Architecture
description: How TruthTable is organized, from SQL front-end to proof.
---

TruthTable is organized as a Rust workspace of focused crates. At a high level,
a query flows through the following stages:

1. **Front-end** — a SQL query is parsed and lowered into an intermediate
   representation of relational operators (`tt-front-end`, `tt-core`).
2. **Planning** — the logical plan is transformed into a proof plan that decides
   how each operator will be proven (`tt-proof-planner`).
3. **Arithmetization** — relational operators (joins, aggregates, sorts, …) are
   encoded into constraints over columns (`tt-arithmetic`, `tt-core`).
4. **Commitment & proving** — the prover commits to the witness columns and
   produces a succinct proof.
5. **Verification** — the verifier checks the proof against the dataset
   commitment and the claimed result.

:::note
This overview is intentionally high-level and will be expanded with details on
each stage. See the [source](https://github.com/arkworks-rs/truth-table) for the
authoritative breakdown of crates.
:::
