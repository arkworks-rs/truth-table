//! Type aliases naming each plan-side pipeline stage.
//!
//! Both prover and verifier start from [`EmptyIr`], share the planning stages
//! ([`OutputPlannedIr`], [`GadgetPlannedIr`]), and then diverge into
//! side-specific IR types defined under
//! [`crate::prover::irs`] / [`crate::verifier::irs`].

use crate::irs::{
    ir::Ir,
    payloads::{EmptyPayload, HintDFPayload},
};

/// The empty intermediate representation — the starting point where no pass
/// has attached any payload yet.
pub type EmptyIr<B> = Ir<B, EmptyPayload>;

/// IR after output planning: each node carries a hint dataframe describing
/// the logical-plan fragment it will execute.
pub type OutputPlannedIr<B> = Ir<B, HintDFPayload>;

/// IR after gadget planning: gadget nodes are attached to their plan parents
/// and the hint dataframes are rewritten to account for gadget I/O.
pub type GadgetPlannedIr<B> = Ir<B, HintDFPayload>;

/// Backwards-compatible alias for [`EmptyIr`].
pub type InitialIr<B> = EmptyIr<B>;
