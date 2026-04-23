//! Intermediate representations (IRs) for the prover’s truth-table pipeline.
//!
//! This module defines type aliases for the various IRs the prover's pipeline, ranging from simple plans for computing the witnesses to fully arithmetized and tracked polynomials ready for a SNARK prover.

use crate::{
    irs::ir::Ir,
    prover::payloads::{
        ArithPayload, CommittedPayload, GadgetReadyPayload, MaterializedPayload, TrackedPayload,
        VirtualizedPayload,
    },
};
use ark_piop::SnarkBackend;

/// The materialized Intermediate Representation with materialized in-memory table payloads.
///
/// This IR represents the stage in the prover's pipeline where the proof tree nodes contain materialized in-memory tables resulting from executing the hint dataframes.
pub type MaterializedIr<B> = Ir<B, MaterializedPayload>;
/// The arithmetized Intermediate Representation with polynomial payloads.
///
/// This IR represents the stage in the prover's pipeline where the proof tree nodes contain arithmetized polynomials derived from the materialized tables.
pub type ArithmetizedIr<B> = Ir<B, ArithPayload<<B as SnarkBackend>::F>>;
/// The committed Intermediate Representation with table oracle payloads.
///
/// This IR represents the stage in the prover's pipeline where each arithmetized table has been committed and serialized into an oracle (commitments only).
pub type CommittedIr<B> = Ir<B, CommittedPayload<B>>;
/// The tracked Intermediate Representation with tracked table payloads.
///
/// This IR represents the stage in the prover's pipeline where the proof tree nodes contain tracked tables; i.e. tables that have commited polynomials and already appended to the prover's transcript.
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;
/// The virtualized Intermediate Representation with virtualized table payloads.
///
/// This IR represents the final stage in the prover's pipeline where the virtual witnesses were added to the proof tree nodes.
pub type VirtualizedIr<B> = Ir<B, VirtualizedPayload<B>>;
pub type GadgetReadyIr<B> = Ir<B, GadgetReadyPayload<B>>;
