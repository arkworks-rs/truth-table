use crate::irs::{nodes::hints::HintDF, tree::Payload};
use arithmetic::table::{ArithTable, TrackedTable};
use datafusion::datasource::TableProvider;
use datafusion::{
    arrow::array::RecordBatch,
    datasource::MemTable,
    prelude::{DataFrame, SessionContext},
};
use datafusion_common::DataFusionError;
use indexmap::IndexMap;
use std::{fmt::Display, sync::Arc};

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
pub type HintDFPayload = PayloadStructure<HintDF>;
pub type MaterializedPayload = PayloadStructure<MaterializedTable>;
pub type ArithPayload<F> = PayloadStructure<ArithTable<F>>;
pub type TrackedPayload<B> = PayloadStructure<TrackedTable<B>>;
pub type VirtualizedPayload<B> = PayloadStructure<TrackedTable<B>>;

impl<T: std::fmt::Display> std::fmt::Display for PayloadStructure<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadStructure::PlanPayload(inner) => write!(f, "PlanPayload({})", inner),
            PayloadStructure::GadgetPayload(entries) => {
                write!(f, "GadgetPayload{{")?;
                for (idx, (key, value)) in entries.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", key, value)?;
                }
                write!(f, "}}")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmptyPayload;
impl Payload for EmptyPayload {}

impl std::fmt::Display for EmptyPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmptyPayload")
    }
}

#[derive(Debug, Clone)]
pub struct MaterializedTable {
    table: Arc<MemTable>,
    row_count: usize,
}
impl MaterializedTable {
    pub fn new(table: MemTable, row_count: usize) -> Self {
        Self {
            table: Arc::new(table),
            row_count,
        }
    }

    pub fn mem_table(&self) -> &MemTable {
        &self.table
    }

    pub fn mem_table_arc(&self) -> Arc<MemTable> {
        Arc::clone(&self.table)
    }

    pub fn batches(&self) -> datafusion_common::Result<Vec<RecordBatch>> {
        let ctx = SessionContext::new();
        let df = ctx.read_table(self.table.clone())?;
        collect_blocking_df(df)
    }
}
impl std::fmt::Display for MaterializedTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cols: Vec<String> = self
            .table
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().to_string())
            .collect();
        write!(
            f,
            "MaterializedTable cols=({}), rows={}",
            cols.join(","),
            self.row_count
        )
    }
}

fn collect_blocking_df(df: DataFrame) -> datafusion_common::Result<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    DataFusionError::Execution("dataframe collection thread panicked".to_string())
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}
