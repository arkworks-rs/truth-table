//! A baseline verifiable database with no proof system.
//!
//! - Commit: the data owner encodes every column as an Arrow IPC stream and
//!   publishes its BLAKE3 hash, together with the column's field and the
//!   table's row count, in a `.colhash` file.
//! - Prove: the prover plans the query, finds the columns its table scans
//!   read, and sends those encoded columns.
//! - Verify: the verifier hashes every received column against the
//!   commitment, decodes it, checks its length against the committed row
//!   count, and runs the query itself on the received columns. A column the
//!   prover left out makes the verifier's own planning fail.
//!
//! Tables are queried as they are: no padding or activator columns.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, BufWriter, Cursor},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

// DataFusion's own arrow and parquet: DataFusion 46 is on arrow 54, the
// crate's `arrow` dependency on 57.
use datafusion::{
    arrow::{
        array::{ArrayRef, RecordBatch, RecordBatchOptions, RecordBatchReader},
        compute::concat_batches,
        datatypes::{Field, Schema, SchemaRef},
        ipc::{reader::StreamReader, writer::StreamWriter},
        util::pretty::pretty_format_batches,
    },
    common::tree_node::TreeNodeRecursion,
    datasource::MemTable,
    logical_expr::LogicalPlan,
    parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder,
    prelude::{SessionConfig, SessionContext},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct TableCommitment {
    table: String,
    num_rows: u64,
    columns: Vec<ColumnCommitment>,
}

#[derive(Serialize, Deserialize)]
struct ColumnCommitment {
    field: Field,
    hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Proof {
    columns: Vec<SentColumn>,
}

#[derive(Serialize, Deserialize)]
struct SentColumn {
    table: String,
    column: String,
    #[serde(with = "serde_bytes")]
    ipc: Vec<u8>,
}

pub struct Table {
    pub name: String,
    pub batch: RecordBatch,
    pub commitment_path: PathBuf,
    /// The prover's copy of the encoded columns, one file per column.
    pub store_dir: PathBuf,
}

impl Table {
    /// A table whose commitment and column store live in `dir`.
    pub fn new(name: impl Into<String>, batch: RecordBatch, dir: &Path) -> Self {
        let name = name.into();
        let store_dir = dir.join("baseline_store").join(&name);
        std::fs::create_dir_all(&store_dir).expect("create store dir");
        Table {
            commitment_path: dir.join(format!("{name}.colhash")),
            store_dir,
            batch,
            name,
        }
    }
}

pub fn load_parquet(path: &Path) -> RecordBatch {
    let file =
        File::open(path).unwrap_or_else(|err| panic!("missing parquet {}: {err}", path.display()));
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("parquet reader")
        .build()
        .expect("parquet reader");
    let schema = reader.schema();
    let batches = reader.collect::<Result<Vec<_>, _>>().expect("read parquet");
    concat_batches(&schema, &batches).expect("concat batches")
}

fn encode_column(field: &Field, array: &ArrayRef) -> Vec<u8> {
    let schema = Arc::new(Schema::new(vec![field.clone()]));
    let batch =
        RecordBatch::try_new(Arc::clone(&schema), vec![Arc::clone(array)]).expect("column batch");
    let mut writer = StreamWriter::try_new(Vec::new(), &schema).expect("ipc writer");
    writer.write(&batch).expect("ipc write");
    writer.into_inner().expect("ipc finish")
}

fn decode_column(bytes: &[u8]) -> Result<(Field, ArrayRef), String> {
    let reader = StreamReader::try_new(Cursor::new(bytes), None).map_err(|e| e.to_string())?;
    let schema = reader.schema();
    let batches = reader
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if schema.fields().len() != 1 {
        return Err("an encoded column must have exactly one field".into());
    }
    let batch = concat_batches(&schema, &batches).map_err(|e| e.to_string())?;
    Ok((schema.field(0).clone(), Arc::clone(batch.column(0))))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new()
        .update_rayon(bytes)
        .finalize()
        .as_bytes()
}

fn session(threads: usize) -> SessionContext {
    // Row order does not matter here (nothing is committed to the result), so
    // DataFusion may use every thread.
    SessionContext::new_with_config(SessionConfig::new().with_target_partitions(threads))
}

/// Splits `batch` into `parts` zero-copy slices, so that a `MemTable` scan
/// runs in parallel.
fn partitions(batch: &RecordBatch, parts: usize) -> Vec<Vec<RecordBatch>> {
    let rows = batch.num_rows();
    let chunk = rows.div_ceil(parts).max(1);
    let mut out: Vec<Vec<RecordBatch>> = (0..rows)
        .step_by(chunk)
        .map(|start| vec![batch.slice(start, chunk.min(rows - start))])
        .collect();
    if out.is_empty() {
        out.push(vec![batch.clone()]);
    }
    out
}

/// Data owner: encodes and hashes every column and writes the commitment.
/// Returns the encoded columns for [`store`].
pub fn commit(table: &Table) -> (TableCommitment, Vec<Vec<u8>>) {
    let schema = table.batch.schema();
    let (columns, blobs): (Vec<_>, Vec<_>) = schema
        .fields()
        .par_iter()
        .zip(table.batch.columns().par_iter())
        .map(|(field, array)| {
            let ipc = encode_column(field, array);
            let commitment = ColumnCommitment {
                field: field.as_ref().clone(),
                hash: hash(&ipc),
            };
            (commitment, ipc)
        })
        .unzip();
    let commitment = TableCommitment {
        table: table.name.clone(),
        num_rows: table.batch.num_rows() as u64,
        columns,
    };
    let file = File::create(&table.commitment_path).expect("create commitment");
    bincode::serialize_into(BufWriter::new(file), &commitment).expect("write commitment");
    (commitment, blobs)
}

/// Hands the encoded columns to the prover.
pub fn store(table: &Table, commitment: &TableCommitment, blobs: Vec<Vec<u8>>) {
    for (column, blob) in commitment.columns.iter().zip(blobs) {
        std::fs::write(
            table
                .store_dir
                .join(format!("{}.arrow", column.field.name())),
            blob,
        )
        .expect("write stored column");
    }
}

fn read_commitment(path: &Path) -> TableCommitment {
    let file = File::open(path).expect("open commitment");
    bincode::deserialize_from(BufReader::new(file)).expect("read commitment")
}

fn committed_schema(commitment: &TableCommitment) -> SchemaRef {
    Arc::new(Schema::new(
        commitment
            .columns
            .iter()
            .map(|c| c.field.clone())
            .collect::<Vec<_>>(),
    ))
}

/// Prover: plans the query against the committed schemas and sends every
/// column a table scan of the optimized plan reads.
pub async fn prove(sql: &str, tables: &[&Table], proof_path: &Path) {
    let ctx = session(1);
    for table in tables {
        let schema = committed_schema(&read_commitment(&table.commitment_path));
        let empty = MemTable::try_new(schema, vec![vec![]]).expect("mem table");
        ctx.register_table(table.name.as_str(), Arc::new(empty))
            .expect("register table");
    }
    let plan = ctx
        .sql(sql)
        .await
        .expect("plan query")
        .into_optimized_plan()
        .expect("optimize plan");

    let mut needed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    plan.apply_with_subqueries(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            let schema = scan.source.schema();
            let indices = scan
                .projection
                .clone()
                .unwrap_or_else(|| (0..schema.fields().len()).collect());
            needed
                .entry(scan.table_name.table().to_string())
                .or_default()
                .extend(indices.iter().map(|&i| schema.field(i).name().clone()));
        }
        Ok(TreeNodeRecursion::Continue)
    })
    .expect("walk plan");

    let mut columns = Vec::new();
    for (table, names) in needed {
        let store_dir = &tables
            .iter()
            .find(|t| t.name == table)
            .expect("scanned table is a bench table")
            .store_dir;
        for column in names {
            let ipc = std::fs::read(store_dir.join(format!("{column}.arrow")))
                .expect("read stored column");
            columns.push(SentColumn {
                table: table.clone(),
                column,
                ipc,
            });
        }
    }
    let file = File::create(proof_path).expect("create proof");
    bincode::serialize_into(BufWriter::new(file), &Proof { columns }).expect("write proof");
}

/// Verifier: checks the received columns against the commitments and runs
/// the query on them.
pub async fn verify(
    sql: &str,
    commitment_paths: &[PathBuf],
    proof_path: &Path,
    threads: usize,
) -> Result<Vec<RecordBatch>, String> {
    let commitments: Vec<TableCommitment> = commitment_paths
        .iter()
        .map(|p| read_commitment(p))
        .collect();
    let file = File::open(proof_path).map_err(|e| e.to_string())?;
    let proof: Proof =
        bincode::deserialize_from(BufReader::new(file)).map_err(|e| e.to_string())?;

    let mut seen = BTreeSet::new();
    for sent in &proof.columns {
        if !seen.insert((&sent.table, &sent.column)) {
            return Err(format!("column {}.{} sent twice", sent.table, sent.column));
        }
    }
    let decoded = proof
        .columns
        .par_iter()
        .map(|sent| {
            let commitment = commitments
                .iter()
                .find(|c| c.table == sent.table)
                .ok_or_else(|| format!("table {} is not committed", sent.table))?;
            let committed = commitment
                .columns
                .iter()
                .find(|c| c.field.name() == &sent.column)
                .ok_or_else(|| format!("column {}.{} is not committed", sent.table, sent.column))?;
            if hash(&sent.ipc) != committed.hash {
                return Err(format!(
                    "column {}.{} does not match its hash",
                    sent.table, sent.column
                ));
            }
            let (field, array) = decode_column(&sent.ipc)?;
            if array.len() as u64 != commitment.num_rows {
                return Err(format!(
                    "column {}.{} has the wrong length",
                    sent.table, sent.column
                ));
            }
            Ok(((sent.table.as_str(), field.name().clone()), (field, array)))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;

    let ctx = session(threads);
    for commitment in &commitments {
        // Committed column order; a table nothing was sent for keeps its
        // committed row count with no columns.
        let (fields, arrays): (Vec<Field>, Vec<ArrayRef>) = commitment
            .columns
            .iter()
            .filter_map(|c| decoded.get(&(commitment.table.as_str(), c.field.name().clone())))
            .map(|(field, array)| (field.clone(), Arc::clone(array)))
            .unzip();
        let schema = Arc::new(Schema::new(fields));
        let batch = RecordBatch::try_new_with_options(
            Arc::clone(&schema),
            arrays,
            &RecordBatchOptions::new().with_row_count(Some(commitment.num_rows as usize)),
        )
        .map_err(|e| e.to_string())?;
        let table =
            MemTable::try_new(schema, partitions(&batch, threads)).map_err(|e| e.to_string())?;
        ctx.register_table(commitment.table.as_str(), Arc::new(table))
            .map_err(|e| e.to_string())?;
    }
    let df = ctx.sql(sql).await.map_err(|e| e.to_string())?;
    df.collect().await.map_err(|e| e.to_string())
}

/// Panics unless `result` is the result of `sql` on the full tables, up to
/// row order.
pub async fn check_result(sql: &str, tables: &[&Table], threads: usize, result: &[RecordBatch]) {
    let ctx = session(threads);
    for table in tables {
        let mem = MemTable::try_new(table.batch.schema(), vec![vec![table.batch.clone()]])
            .expect("mem table");
        ctx.register_table(table.name.as_str(), Arc::new(mem))
            .expect("register table");
    }
    let reference = ctx
        .sql(sql)
        .await
        .expect("plan")
        .collect()
        .await
        .expect("run");
    let sorted_rows = |batches: &[RecordBatch]| {
        let rendered = pretty_format_batches(batches).expect("format").to_string();
        let mut lines: Vec<String> = rendered.lines().map(str::to_string).collect();
        lines.sort();
        lines
    };
    assert_eq!(
        sorted_rows(result),
        sorted_rows(&reference),
        "verifier result differs from the query on the full tables: {sql}"
    );
}

/// Median wall-clock milliseconds of `iters` runs of `f`; single runs of
/// sub-millisecond phases are mostly noise.
pub fn median_ms(iters: usize, mut f: impl FnMut()) -> f64 {
    let mut samples: Vec<f64> = (0..iters)
        .map(|_| {
            let start = Instant::now();
            f();
            start.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

pub fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// The thread count `RAYON_NUM_THREADS` sets (default 1), and a tokio
/// runtime with that many workers for DataFusion.
pub fn threads_and_runtime() -> (usize, tokio::runtime::Runtime) {
    let threads: usize = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .expect("tokio runtime");
    (threads, rt)
}
