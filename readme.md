![dbsnark logo](docs/assets/logo.png)

# Rust Workspace: DB-SNARK

Welcome to the **DB-SNARK** Rust workspace! This repository contains multiple Rust crates organized in a Cargo workspace to provide a modular, maintainable codebase.

## Workspace Structure

This project is structured as a Cargo workspace, with each crate serving a specific purpose. Below is a list of the crates included:

### Crates

- [`ark-piop`](./ark-piop)

  - **Description:** Implments the core functionalities of the prover and the verifier in the argument system. Almost all other crate depend on this crate.
  - **Example:** Functionalities for polynomial arithmetics, committing to polynomials, maintaing and tracking the transcript, etc

- [`col-toolbox`](./col-toolbox)

  - **Description:** Provides useful argument systems for single or multiple columns. These arguments are composed in [`ra-toolbox`](./ra-toolbox/).
  - **Example:** Some examples of the tools:

    1. Proving that a column has no duplicate: [`NoDupCheck`](./col-toolbox/src/no_dup_check/)

    2. Proving that a column has no zeros: [`NoZeroCheck`](./col-toolbox/src/no_zeros_check/)

    3. Proving that a column is a permutation of another column: [`PermCheck`](./col-toolbox/src/perm_check/)

    <div style="width:100%; text-align:center;">
      <div style="border:1px solid #ccc; padding:5px 10px; border-radius:6px; display:inline-block;">
        <strong>Column A is the result of applying operator X on column B</strong>
      </div>
    </div>

- [`col-toolbox-bench`](./col-toolbox-bench/)

  - **Description:** a crate for benchmarking the tools in [`col-toolbox`](./col-toolbox)

- [`ra-toolbox`](./ra-toolbox)

  - **Description:** Provides argument systems for relational algebraic operations. These arguments take in two tables, and produce arguments of the form

<div style="width:100%; text-align:center;">
  <div style="border:1px solid #ccc; padding:5px 10px; border-radius:6px; display:inline-block;">
    <strong>Table A is the result of applying operator X on table B</strong>
  </div>
</div>

- **Example:** Some examples of the tools:

  1. Proving that the selection was done correctly in [`select`](./ra-toolbox/src/select/)
  2. Proving that the group-by was done correctly in [`group-by`](./ra-toolbox/src/group-by/)

- [`ra-toolbox-bench`](./ra-toolbox-bench/)

  - **Description:** a crate for benchmarking the tools in [`ra-toolbox`](./ra-toolbox)

- [`arithmetic`](./arithmetic/)

  - **Description:** a crate for encoding/decoding various database data-types to/from finite field elements

- [`piop-tree`](./piop-tree/)
  - **Description:** contains a diagram of dependencies between different piops in the repo. It's useful for understanding the code-base and debugging.

---

## Getting Started

First create and fill the 'imdb_paruqet' folder in ra-toolbox-bench directory, the run:

```bash

cargo bench --bench group_by_count;
cargo bench --bench group_by_sum;
cargo bench --bench select_eq;

```
