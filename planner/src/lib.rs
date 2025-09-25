//! Front-end crate for dbSNARK system.
//! This crate is responsible for translating DataFusion logical plans into
//! proof plans and witness plans that can be executed to generate a proof for
//! the logical plan.

pub mod arithmetized_plan;
pub mod ra_proof_plan;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod virtualized_plan;
pub mod witness_plan;
