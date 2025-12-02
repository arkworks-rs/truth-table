use std::fmt::Display;

use arithmetic::table::{ArithTable, TrackedTable};
use datafusion::{datasource::MemTable, prelude::DataFrame};
use indexmap::IndexMap;

use crate::irs::{nodes::hints::HintDF, tree::Payload};

#[derive(Debug)]
pub enum PayloadStructure<T> {
    PlanPayload(T),
    GadgetPayload(IndexMap<String, T>),
}
impl<T: std::fmt::Debug + Display + 'static> Payload for PayloadStructure<T> {}
pub type HintDFPayload = PayloadStructure<HintDF>;
pub type MaterializedPayload = PayloadStructure<MaterializedTable>;
pub type ArithPayload<F> = PayloadStructure<ArithTable<F>>;
pub type TrackedPayload<B> = PayloadStructure<TrackedTable<B>>;

impl<T: std::fmt::Display> std::fmt::Display for PayloadStructure<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadStructure::PlanPayload(inner) => write!(f, "PlanPayload({})", inner),
            PayloadStructure::GadgetPayload(entries) => {
                write!(f, "GadgetPayload{{")?;
                let mut first = true;
                for (key, value) in entries {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    write!(f, "{}: {}", key, value)?;
                }
                write!(f, "}}")
            }
        }
    }
}

#[derive(Debug)]
pub struct EmptyPayload;
impl Payload for EmptyPayload {}

impl std::fmt::Display for EmptyPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmptyPayload")
    }
}

#[derive(Debug)]
pub struct MaterializedTable(MemTable);
impl std::fmt::Display for MaterializedTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
