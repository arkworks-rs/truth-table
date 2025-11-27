use arithmetic::table::{ArithTable, TrackedTable};
use datafusion::{datasource::MemTable, prelude::DataFrame};
use indexmap::IndexMap;

use crate::irs::tree::Payload;

#[derive(Debug)]
pub enum PayloadStructure<T> {
    PlanPayload(T),
    GadgetPayload(IndexMap<String, T>),
}
impl<T: std::fmt::Debug + 'static> Payload for PayloadStructure<T> {}
pub type DataFramePayload = PayloadStructure<DataFrame>;
pub type MemTablePayload = PayloadStructure<MemTable>;
pub type ArithPayload<F> = PayloadStructure<ArithTable<F>>;
pub type TrackedPayload<B> = PayloadStructure<TrackedTable<B>>;
