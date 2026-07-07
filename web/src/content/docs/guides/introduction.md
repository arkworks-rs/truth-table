---
title: Introduction
description: What TruthTable is and the problem it solves.
---

TruthTable is a **verifiable query engine**. It lets an untrusted server run a
SQL query over a committed dataset and return the answer along with a succinct
cryptographic proof that the answer is correct. A verifier can check that proof
far faster than re-executing the query, and without access to the full dataset.

## The problem

When you outsource query execution — to a cloud provider, a data marketplace,
or an off-chain node — you normally have to *trust* that the operator ran the
query faithfully. TruthTable removes that trust assumption: a wrong or tampered
result simply fails verification.

## What makes it different

- **Complete TPC-H support.** TruthTable targets the entire TPC-H benchmark,
  including joins, aggregations, sorts, and nested subqueries.
- **Succinct proofs.** Verification cost is small and roughly independent of the
  size of the underlying data.
- **Built in Rust on arkworks.** The system is implemented on top of the
  [arkworks](https://arkworks.rs) ecosystem.

## Where to next

- [Installation](/guides/installation/) — build the project from source.
- [Quick Start](/guides/quick-start/) — prove and verify your first query.
