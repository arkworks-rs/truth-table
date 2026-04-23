//! Per-node payload envelopes used by the IR.
//!
//! Each pipeline stage (see [`crate::irs::shared_ir`]) picks one payload type
//! that wraps the stage's actual data — typically a [`nodes::hints::HintDF`]
//! for plan-side stages and an `IndexMap<String, T>` keyed by gadget slot for
//! gadget-side stages. Both shapes travel as a [`PayloadStructure`] so
//! generic pass code does not have to branch on node kind.

use crate::irs::{nodes::hints::HintDF, tree::Payload};
use indexmap::IndexMap;
use std::fmt::Display;

/// Per-node payload envelope: a single value for plan nodes, a keyed map for
/// gadget nodes.
#[derive(Debug)]
pub enum PayloadStructure<T> {
    /// Plan-side payload carrying a single value for the node.
    PlanPayload(T),
    /// Gadget-side payload carrying one value per named gadget slot.
    GadgetPayload(IndexMap<String, T>),
}

impl<T: Clone> Clone for PayloadStructure<T> {
    fn clone(&self) -> Self {
        match self {
            PayloadStructure::PlanPayload(inner) => PayloadStructure::PlanPayload(inner.clone()),
            PayloadStructure::GadgetPayload(map) => PayloadStructure::GadgetPayload(map.clone()),
        }
    }
}
impl<T: std::fmt::Debug + Display + 'static> Payload for PayloadStructure<T> {}

/// Payload envelope used by plan-side IR stages (output planning, gadget
/// planning) that carry a [`HintDF`] dataframe per node or per gadget slot.
pub type HintDFPayload = PayloadStructure<HintDF>;

impl<T: std::fmt::Display> std::fmt::Display for PayloadStructure<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadStructure::PlanPayload(inner) => write!(f, "PlanPayload({})", inner),
            PayloadStructure::GadgetPayload(entries) => {
                if entries.is_empty() {
                    return write!(f, "GadgetPayload{{}}");
                }
                write!(f, "GadgetPayload")?;
                for (key, value) in entries.iter() {
                    write!(f, "\n{}: {}", key, value)?;
                }
                Ok(())
            }
        }
    }
}

/// Zero-information payload used by the starting IR
/// ([`crate::irs::shared_ir::EmptyIr`]) before any pass has run.
#[derive(Debug, Clone)]
pub struct EmptyPayload;
impl Payload for EmptyPayload {}

impl std::fmt::Display for EmptyPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmptyPayload")
    }
}
