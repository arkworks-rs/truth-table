---
title: Quick Start
description: Prove and verify your first query with TruthTable.
---

:::caution
This page is a placeholder. The command-line workflow is still being finalized —
the steps below illustrate the intended flow and will be updated to match the
shipped CLI.
:::

At a high level, using TruthTable involves three steps:

1. **Commit** to a dataset, producing a short commitment the verifier trusts.
2. **Prove** — run a SQL query against the committed data to get a result plus a
   proof.
3. **Verify** — check the proof against the commitment and the claimed result.

```sh
# Illustrative — subject to change.
tt commit  ./data            # -> dataset commitment
tt prove   ./query.sql       # -> result + proof
tt verify  ./proof           # -> accept / reject
```

Once the CLI stabilizes, this guide will walk through a complete end-to-end
TPC-H example.
