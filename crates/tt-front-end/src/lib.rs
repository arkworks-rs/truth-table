//! The three roles of the truth-table protocol and the artifacts they
//! exchange (keys and proofs, in [`structs`]):
//! - the data owner commits source tables into `.oracle` artifacts;
//! - the prover executes a query and produces a proof;
//! - the verifier checks the proof and the claimed result against the
//!   `.oracle` artifacts.

pub mod data_owner;
pub mod prover;
pub mod shared;
pub mod structs;
pub mod verifier;
