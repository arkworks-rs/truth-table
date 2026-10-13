use crate::irs::payloads::PayloadStructure;
use crate::session::session_context;
use arithmetic::table::ArithTable;
use arithmetic::table_oracle::TrackedTableOracle;
use datafusion::datasource::TableProvider;
use datafusion::{arrow::array::RecordBatch, datasource::MemTable};
use std::sync::Arc;

pub type MaterializedPayload = PayloadStructure<MaterializedTable>;
pub type ArithPayload<F> = PayloadStructure<ArithTable<F>>;
pub type TrackedPayload<B> = PayloadStructure<TrackedTableOracle<B>>;
pub type VirtualizedPayload<B> = PayloadStructure<TrackedTableOracle<B>>;
pub type GadgetReadyPayload<B> = PayloadStructure<TrackedTableOracle<B>>;

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
