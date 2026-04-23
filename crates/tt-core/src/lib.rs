//! Core intermediate representation and proving / verifying pass pipelines.
//!
//! `tt-core` is the engine room of the truth-table protocol. It owns:
//!
//! - The IR (`irs`) — plan nodes, gadget nodes, expressions, and the tree
//!   structure that the prover and verifier both operate on.
//! - The prover-side passes (`prover::passes`) — output planning, gadget
//!   planning, materialization, arithmetization, commitment, tracking,
//!   virtualization, gadget initialization, and final proving.
//! - The matching verifier-side passes (`verifier::passes`) that consume
//!   optimization hints and commitments to replay the prover's plan and
//!   check the resulting arguments.
//! - The shared context oracles (`ctx_oracles`) that carry committed-table
//!   metadata between prover and verifier, and the crate-wide error type
//!   (`errors::TTError`, `errors::TTResult`).
//!
//! Most users should depend on the `tt-front-end` crate instead; this one is
//! the lower-level library that `tt-front-end` is built on top of.

pub mod ctx_oracles;
pub mod errors;
pub mod irs;
pub mod prover;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod verifier;
