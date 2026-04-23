# Security Policy

## Supported versions

TruthTable is research software and is not yet versioned for production use. Security fixes land on `main` only until a stable release is tagged.

## Reporting a vulnerability

If you believe you have found a security issue in TruthTable — for example a soundness bug in the proving pipeline, a way to forge a proof that verifies incorrectly, a commitment-binding problem, or anything that could affect the integrity of a verifier's decision — **please do not open a public GitHub issue**.

Instead, email:

- Alireza Shirzad — alr.shirzad@gmail.com

Include:

- A description of the issue and its impact.
- Concrete reproduction steps or a proof-of-concept (minimal Rust code or a parquet input is ideal).
- The commit hash / version you tested against.
- Any suggested mitigation if you have one.

We aim to acknowledge reports within 5 business days. After we confirm the issue, we will coordinate a fix and a disclosure window with you before announcing it publicly.

## Non-security bugs

Regular correctness or crash bugs should go through the usual [GitHub issues](https://github.com/alireza-shirzad/truth-table/issues) — those don't need the private disclosure process.
