//! The per-node payloads of the IR.

use crate::irs::{nodes::hints::HintDF, tree::Payload};
use indexmap::IndexMap;
use std::fmt::Display;

/// A node's payload: one value for a plan node, one value per named slot for
/// a gadget node. One type for both lets generic pass code ignore the node
/// kind.
#[derive(Debug)]
pub enum PayloadStructure<T> {
    PlanPayload(T),
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

/// The payload of the planning stages.
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

/// The payload of the IR before any pass has run.
#[derive(Debug, Clone)]
pub struct EmptyPayload;
impl Payload for EmptyPayload {}

impl std::fmt::Display for EmptyPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmptyPayload")
    }
}
