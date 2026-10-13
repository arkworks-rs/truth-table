use crate::session::session_context;
use arithmetic::table::{ArithTable, TrackedTable};
use arithmetic::table_oracle::ArithTableOracle;
use datafusion::datasource::TableProvider;
use datafusion::{arrow::array::RecordBatch, datasource::MemTable};
use std::sync::Arc;

use crate::irs::payloads::PayloadStructure;

pub type MaterializedPayload = PayloadStructure<MaterializedTable>;
pub type ArithPayload<F> = PayloadStructure<ArithTable<F>>;
pub type CommittedPayload<B> = PayloadStructure<ArithTableOracle<B>>;
pub type TrackedPayload<B> = PayloadStructure<TrackedTable<B>>;
pub type VirtualizedPayload<B> = PayloadStructure<TrackedTable<B>>;
pub type GadgetReadyPayload<B> = PayloadStructure<TrackedTable<B>>;

#[derive(Debug, Clone)]
pub struct MaterializedTable {
    table: Arc<MemTable>,
    row_count: usize,
    batches: Option<Vec<RecordBatch>>,
}
impl MaterializedTable {
    pub fn new(table: MemTable, row_count: usize) -> Self {
        Self {
            table: Arc::new(table),
            row_count,
            batches: None,
        }
    }

    pub fn new_with_batches(table: MemTable, row_count: usize, batches: Vec<RecordBatch>) -> Self {
        Self {
            table: Arc::new(table),
            row_count,
            batches: Some(batches),
        }
    }

    pub fn mem_table(&self) -> &MemTable {
        &self.table
    }
    pub fn row_count(&self) -> usize {
        self.row_count
    }

    pub fn mem_table_arc(&self) -> Arc<MemTable> {
        Arc::clone(&self.table)
    }

    pub fn batches(&self) -> datafusion_common::Result<Vec<RecordBatch>> {
        if let Some(batches) = &self.batches {
            return Ok(batches.clone());
        }
        let ctx = session_context();
        let df = ctx.read_table(self.table.clone())?;
        crate::session::block_on(df.collect())
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
