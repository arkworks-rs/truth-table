---
title: Installation
description: Build TruthTable from source.
---

:::note
TruthTable is under active development. These steps build the project from
source; packaged releases will be documented here as they become available.
:::

## Prerequisites

- A recent **Rust** toolchain (the workspace uses the 2024 edition — install via
  [rustup](https://rustup.rs)).
- `git`.

## Clone and build

```sh
git clone https://github.com/arkworks-rs/truth-table.git
cd truth-table
cargo build --release
```

The workspace is split into several crates (`tt-core`, `tt-arithmetic`,
`tt-exec`, and others). Building at the workspace root compiles the default
members; some benchmark-only crates are excluded by default and built
explicitly when needed.

## Next

Head to the [Quick Start](/guides/quick-start/) to run your first proof.
