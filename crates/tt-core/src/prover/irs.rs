//! Type aliases for the prover-side stages of the IR.

use crate::{
    irs::ir::Ir,
    prover::payloads::{
        ArithPayload, CommittedPayload, GadgetReadyPayload, MaterializedPayload, TrackedPayload,
        VirtualizedPayload,
    },
};
use ark_piop::SnarkBackend;

/// Each node holds the in-memory table its hint dataframe evaluates to.
pub type MaterializedIr<B> = Ir<B, MaterializedPayload>;
/// Each materialized table is turned into polynomials.
pub type ArithmetizedIr<B> = Ir<B, ArithPayload<<B as SnarkBackend>::F>>;
/// Each arithmetized table is committed; the payload holds the commitments
/// only.
pub type CommittedIr<B> = Ir<B, CommittedPayload<B>>;
/// Each node's table is a set of committed polynomials already appended to
/// the prover's transcript.
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;
/// The tracked IR with the virtual witnesses added.
pub type VirtualizedIr<B> = Ir<B, VirtualizedPayload<B>>;
/// The virtualized IR with the gadget payloads prepared.
pub type GadgetReadyIr<B> = Ir<B, GadgetReadyPayload<B>>;
