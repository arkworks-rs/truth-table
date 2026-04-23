//! CLI runners and end-to-end helpers for the truth-table protocol.
//!
//! `tt-exec` builds the `tt` binary (see `main.rs`) and exposes the same
//! subcommands as a library:
//!
//! - [`setup`] — generate a proving / verifying key pair
//! - [`commit`] — commit a Parquet table into a `.oracle` artifact
//! - [`prove`] — run a SQL query and produce a [`front_end::structs::TTProof`]
//! - [`verify`] — check a proof against the committed oracle and claimed result
//!
//! Each subcommand follows a builder-then-`run` convention, and
//! [`test_utils::prove_and_verify_query`] is a one-call helper that chains all
//! four stages together — used by the crate's integration tests and by the
//! `quickstart` example.

pub mod cmd;
pub mod commit;
pub mod paths;
pub mod prove;
pub(crate) mod runtime;
pub mod setup;
pub mod test_utils;
pub mod verify;
