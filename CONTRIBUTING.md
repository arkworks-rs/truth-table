# Contributing to TruthTable

Thanks for your interest in contributing! This document covers how to set up a
development environment, our expectations for changes, and how to submit them.

## Before you start

- Please read the [Code of Conduct](CODE_OF_CONDUCT.md).
- TruthTable is licensed under [PolyForm Noncommercial 1.0.0](LICENSE); by
  submitting a contribution you agree that it can be distributed under the same
  terms.
- For large or architectural changes, please open an issue first to discuss the
  approach.

## Development setup

TruthTable is a Rust workspace. You need:

- A stable Rust toolchain (pinned in [`rust-toolchain.toml`](rust-toolchain.toml)).
- `just` (task runner) — install via your package manager or `cargo install just`.
- Python 3 + pandas/matplotlib if you want to regenerate the paper figures.

Clone and build:

```bash
git clone https://github.com/alireza-shirzad/truth-table
cd truth-table
cargo build --workspace
cargo test --workspace
```

The repo uses some patched Arkworks dependencies during development (see
[`Cargo.toml`](Cargo.toml) `[patch.crates-io]`). This is why it can't be
published to crates.io yet; see [Publishing](#publishing) below.

## Running the test suite

```bash
just test           # full test suite as CI runs it
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

All four must pass before opening a PR — the CI gate enforces them.

## Before you open a PR

1. **Keep the scope focused.** One logical change per PR. If a refactor is needed
   to land a feature, land the refactor first in its own PR.
2. **Don't introduce new `unwrap()` / `expect()` / `todo!()` / `panic!()`** in
   non-test code without a short comment explaining why it's safe (or a tracking
   issue if it's a stub).
3. **Add tests.** Unit tests co-located with the module, integration tests under
   `crates/<crate>/tests/`. If you're adding a new SQL operator or gadget, add
   at least one end-to-end test that goes through the full prover → verifier
   flow on a small input.
4. **Run the CI commands above locally** — the workspace is pinned to
   `warnings = "deny"`, so even stray unused imports will fail CI.
5. **Write descriptive commit messages** — we don't have strict conventional-commit
   rules, but the first line should be a clear one-liner and the body should
   explain *why*, not *what* (the diff explains the what).

## Style

- Follow `rustfmt` defaults (enforced by CI).
- Prefer descriptive, non-abbreviated names (we have `comitments` → `commitments`
  debt already; don't add more).
- Doc comments (`///`) on anything `pub`. Crate-level `//!` docs on each `lib.rs`
  / `mod.rs` where it makes sense.
- For larger changes, a short architecture comment at the top of a module is
  often more useful than per-function docs.

## Publishing

The `tt-*` crates currently cannot be published to crates.io. Two separate git
sources in the dependency graph both block `cargo publish`:

1. The workspace `[patch.crates-io]` section points several Arkworks crates at
   git master (we depend on fixes that have not yet made it into a tagged
   release).
2. The `divan` workspace dependency is a git pin
   (`divan = { git = "https://github.com/alireza-shirzad/divan.git" }`) because
   we use an unreleased patch.

`cargo publish` refuses any crate whose dependency graph contains a git
source, so either one alone is sufficient to block publication.

Until those git sources can be dropped, consumers have two supported paths:

- **`cargo install --git`**, or
- a git dependency in their own `Cargo.toml`:
  ```toml
  tt-front-end = { git = "https://github.com/alireza-shirzad/truth-table" }
  ```

To unblock crates.io publishing:

- For the Arkworks patches: wait for an Arkworks release that contains the
  commits we depend on and delete the `[patch.crates-io]` block, or vendor the
  affected patches into this workspace.
- For the `divan` pin: switch to a released crates.io version of `divan` (or
  upstream the patch and bump to the release that includes it).

Both must be resolved before `cargo publish` will succeed.

## Reporting bugs / asking questions

Open a GitHub issue. Include:

- What you ran (exact command or code snippet).
- What you expected.
- What actually happened (full error output, not just the last line).
- Your toolchain version (`rustc --version`), OS, and anything else non-default.

For **security issues**, please do *not* open a public issue. See [SECURITY.md](SECURITY.md).
