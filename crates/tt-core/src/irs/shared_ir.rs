//! Type aliases for the planning stages of the IR, which the prover and the
//! verifier share. The later stages are in [`crate::prover::irs`] and
//! [`crate::verifier::irs`].

use crate::irs::{
    ir::Ir,
    payloads::{EmptyPayload, HintDFPayload},
};

/// The starting point: no pass has attached a payload.
pub type EmptyIr<B> = Ir<B, EmptyPayload>;

/// After output planning: each node carries a hint dataframe describing the
/// logical-plan fragment it will execute.
pub type OutputPlannedIr<B> = Ir<B, HintDFPayload>;

/// After gadget planning: gadget nodes are attached to their plan parents
/// and the hint dataframes are rewritten to account for gadget I/O.
pub type GadgetPlannedIr<B> = Ir<B, HintDFPayload>;

pub type InitialIr<B> = EmptyIr<B>;
