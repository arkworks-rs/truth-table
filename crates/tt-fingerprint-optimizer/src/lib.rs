//! Offline evaluation of the fingerprint rules.
//!
//! This crate is data-owner-side tooling — it never runs inside the prover or
//! verifier, and `commit` does not need it: the rules themselves live in
//! `tt-arithmetic`. It prices a rule on a synthetic LIKE workload under the
//! measured prover cost model, and fits that model to measured proofs.
//!
//! - [`corpus`]: load a string column; row bitsets per fingerprint feature.
//! - [`workload`]: synthetic LIKE patterns filling six selectivity regimes.
//! - [`model`]: the measured prover cost model of a LIKE query.
//! - [`pricing`]: price a workload under an assignment, bins chosen per query.

pub mod corpus;
pub mod model;
pub mod pricing;
pub mod workload;

// Prover driver for measuring the cost model's points. Behind the
// `calibration` feature so the default build never depends on the prover
// stack.
#[cfg(feature = "calibration")]
pub mod calibration;
