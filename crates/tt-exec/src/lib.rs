//! The `tt` binary (`src/bin/tt.rs`) and its subcommands as a library:
//! [`setup`], [`commit`], [`prove`] and [`verify`], each a builder and a
//! runner. [`test_utils::prove_and_verify_query`] chains the four stages for
//! the integration tests.

pub mod backend;
pub mod cmd;
pub mod commit;
pub mod paths;
pub mod prove;
pub(crate) mod runtime;
pub mod setup;
pub mod stats_jsonl;
pub mod test_utils;
pub mod tracing_setup;
pub mod verify;
