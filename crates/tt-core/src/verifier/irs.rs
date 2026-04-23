//! Intermediate representations (IRs) for the verifier’s truth-table pipeline.
//!
//! This module defines type aliases for the various IRs the verifier's pipeline, ranging from simple plans for computing the witnesses to fully arithmetized and tracked polynomials ready for a SNARK verifier.

use crate::{
    irs::ir::Ir,
    verifier::payloads::{GadgetReadyPayload, TrackedPayload, VirtualizedPayload},
};

/// The tracked Intermediate Representation with tracked table payloads.
///
/// This IR represents the stage in the verifier's pipeline where the proof tree nodes contain tracked tables; i.e. tables that have commited polynomials and already appended to the verifier's transcript.
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;
/// The virtualized Intermediate Representation with virtualized table payloads.
///
/// This IR represents the final stage in the verifier's pipeline where the virtual witnesses were added to the proof tree nodes.
pub type VirtualizedIr<B> = Ir<B, VirtualizedPayload<B>>;
/// The gadget-ready Intermediate Representation with gadget-initialized payloads.
///
/// This IR represents the stage after gadget initialization where gadget-specific payloads
/// have been prepared on top of the virtualized IR.
pub type GadgetReadyIr<B> = Ir<B, GadgetReadyPayload<B>>;
