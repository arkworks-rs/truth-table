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
