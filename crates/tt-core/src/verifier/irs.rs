//! Type aliases for the verifier-side stages of the IR.

use crate::{
    irs::ir::Ir,
    verifier::payloads::{GadgetReadyPayload, TrackedPayload, VirtualizedPayload},
};

/// Each node's table is a set of committed oracles already appended to the
/// verifier's transcript.
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;
/// The tracked IR with the virtual witnesses added.
pub type VirtualizedIr<B> = Ir<B, VirtualizedPayload<B>>;
/// The virtualized IR with the gadget payloads prepared.
pub type GadgetReadyIr<B> = Ir<B, GadgetReadyPayload<B>>;
