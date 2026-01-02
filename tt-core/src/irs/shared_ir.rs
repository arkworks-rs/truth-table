use crate::irs::{
    ir::Ir,
    payloads::{EmptyPayload, HintDFPayload},
};

/// The empty Intermediate Representation with empty payloads.
///
/// This IR represents the starting point where the proof tree nodes contain no additional
/// information.
pub type EmptyIr<B> = Ir<B, EmptyPayload>;
/// The planned Intermediate Representation with hint dataframe payloads.
///
/// This IR represents the stage where the proof tree nodes contain hint dataframes (or logical
/// plans) that will be executed in later stages.
pub type PlannedIr<B> = Ir<B, HintDFPayload>;

/// Backwards-compatible alias for the empty IR.
pub type InitialIr<B> = EmptyIr<B>;
