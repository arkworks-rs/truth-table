//! The IR of the truth-table protocol and the passes that prove and verify it.
//!
//! The prover and the verifier build the same tree of plan and gadget nodes
//! (`irs`) and run mirrored pass pipelines over it (`prover::passes`,
//! `verifier::passes`). `tt-front-end` is the crate to depend on; it is built
//! on this one.

pub mod ctx_oracles;
pub mod errors;
pub mod irs;
pub mod prover;
pub mod session;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod verifier;
