use crate::irs::{
    ir::Ir,
    payloads::EmptyPayload,
};

/// The empty Intermediate Representation with empty payloads.
///
/// This IR represents the starting point where the proof tree nodes contain no additional
/// information.
pub type EmptyIr<B> = Ir<B, EmptyPayload>;
/// Backwards-compatible alias for the empty IR.
pub type InitialIr<B> = EmptyIr<B>;
