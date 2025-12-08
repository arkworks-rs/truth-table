use crate::irs::payloads::PayloadStructure;
use arithmetic::table::{ArithTable, TrackedTable};
use datafusion::datasource::TableProvider;
use datafusion::{
    arrow::array::RecordBatch,
    datasource::MemTable,
    prelude::{DataFrame, SessionContext},
};
use datafusion_common::DataFusionError;
use std::sync::Arc;

pub type MaterializedPayload = PayloadStructure<MaterializedTable>;
pub type ArithPayload<F> = PayloadStructure<ArithTable<F>>;
pub type TrackedPayload<B> = PayloadStructure<TrackedTable<B>>;
pub type VirtualizedPayload<B> = PayloadStructure<TrackedTable<B>>;

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
