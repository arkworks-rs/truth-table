//! Front-end entry points for the truth-table protocol.
//!
//! This crate packages the three user-facing roles in the system:
//! - the data owner, which commits source tables into `.oracle` artifacts
//! - the prover, which executes a query and produces a proof
//! - the verifier, which verifies the proof against `.oracle` context
//!   and checks the prover's claimed result
//!
//! It also defines the boundary artifact types exchanged between those roles,
//! such as keys and proofs.

/// Data-owner role that commits to tables and produced .oracle artifacts.
pub mod data_owner;
/// Prover role that executes queries and produces truth-table proofs.
pub mod prover;
/// Shared planning/session configuration reused by prover, verifier, and data owner.
pub mod shared;
/// Shared proof and key artifact structs used at the front-end boundary.
pub mod structs;
/// Verifier role that verifies if a result is correct given the query, .oracle artifacts, and a proof from the prover.
pub mod verifier;
