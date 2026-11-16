//! The no-proof baseline (`tt_third_party_bench::baseline`) on the TPC-H
//! queries TruthTable is benchmarked on: the `_tt` variants over the TPC-H
//! tables and the `_pgn` variants over the `_poneglyph` tables, with the same
//! SQL as TruthTable's benches but on the tables without padding or system
//! columns.
//!
//! One line per committed table and per query:
//!   table sf=<sf> name=<t> rows=<n> commit_ms=<ms> commitment_bytes=<b>
//!   query sf=<sf> variant=<tt|pgn> q=<n> prove_ms=<ms> proof_bytes=<b> verify_ms=<ms> execute_ms=<ms> result_rows=<n>
//!
//! `execute_ms` is plain execution: the query on the full tables, unverified.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use datafusion::arrow::{
    array::{BooleanArray, RecordBatch},
    compute::filter_record_batch,
};
use tpch_data::{Variant, generate_parquet_scale, query_spec};
use tt_third_party_bench::baseline::{
    Table, check_result, commit, execute, file_len, load_parquet, median_ms, prove, store,
    threads_and_runtime, verify,
};

// The scale factors of the TruthTable TPC-H sweeps: 0.05 and 0.1 for the
// `_tt` queries, 0.01 to 0.04 for the Poneglyph comparison.
const SCALE_FACTORS: &[f64] = &[0.01, 0.02, 0.04, 0.05, 0.1];

// The queries with a `_tt` bench (`tt-exec/benches/tpch`).
const TT_QUERIES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 17, 18, 19, 20];
const PGN_QUERIES: &[u8] = &[1, 3, 5, 8, 9, 18];

const ITERS: usize = 5;

/// The `_poneglyph` tables exist only padded: keeps the active rows and
/// drops the system columns.
fn strip_padding(batch: RecordBatch) -> RecordBatch {
    let schema = batch.schema();
    let activator = batch
        .column(schema.index_of("__activator__").expect("activator column"))
        .as_any()
        .downcast_ref::<BooleanArray>()
        .expect("boolean activator")
        .clone();
    let active = filter_record_batch(&batch, &activator).expect("filter active rows");
    let keep: Vec<usize> = (0..schema.fields().len())
        .filter(|&i| !schema.field(i).name().starts_with("__"))
        .collect();
    active.project(&keep).expect("drop system columns")
}

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (threads, rt) = threads_and_runtime();

    println!("threads: {threads}");
    println!("iterations: {ITERS}");
    println!("scale_factors: {SCALE_FACTORS:?}");

    for &sf in SCALE_FACTORS {
        let sf_dir = bench_root
            .join("artifact")
            .join("tpch")
            .join(format!("sf_{sf}"));
        // `generate_parquet_scale` writes the padded tables to `data` and the
        // raw ones to the sibling `orig-data`.
        let padded_dir = sf_dir.join("data");
        let raw_dir = sf_dir.join("orig-data");
        if !raw_dir.join("lineitem.parquet").exists()
            || !padded_dir.join("lineitem_poneglyph.parquet").exists()
        {
            generate_parquet_scale(sf, &padded_dir);
        }
        let commit_dir = sf_dir.join("baseline");
        std::fs::create_dir_all(&commit_dir).expect("create baseline dir");

        let specs: Vec<(Variant, &str, u8)> = TT_QUERIES
            .iter()
            .map(|&q| (Variant::Tt, "tt", q))
            .chain(PGN_QUERIES.iter().map(|&q| (Variant::Pgn, "pgn", q)))
            .collect();
        let table_names: BTreeSet<&str> = specs
            .iter()
            .flat_map(|&(variant, _, q)| query_spec(q, variant).tables.iter().copied())
            .collect();

        let tables: Vec<Arc<Table>> = table_names
            .iter()
            .map(|&name| {
                let batch = if name.ends_with("_poneglyph") {
                    strip_padding(load_parquet(&padded_dir.join(format!("{name}.parquet"))))
                } else {
                    load_parquet(&raw_dir.join(format!("{name}.parquet")))
                };
                let table = Table::new(name, batch, &commit_dir);
                let commit_ms = median_ms(ITERS, || {
                    commit(&table);
                });
                let (commitment, blobs) = commit(&table);
                store(&table, &commitment, blobs);
                println!(
                    "table sf={sf} name={name} rows={} commit_ms={commit_ms:.4} commitment_bytes={}",
                    table.batch.num_rows(),
                    file_len(&table.commitment_path)
                );
                Arc::new(table)
            })
            .collect();

        for (variant, label, q) in specs {
            let spec = query_spec(q, variant);
            let query_tables: Vec<&Table> = spec
                .tables
                .iter()
                .map(|name| {
                    tables
                        .iter()
                        .find(|t| t.name == *name)
                        .expect("committed table")
                        .as_ref()
                })
                .collect();
            let commitment_paths: Vec<PathBuf> = query_tables
                .iter()
                .map(|t| t.commitment_path.clone())
                .collect();
            let proof_path = commit_dir.join(format!("{label}_q{q}.proof"));

            let prove_ms = median_ms(ITERS, || {
                rt.block_on(prove(spec.sql, &query_tables, &proof_path));
            });
            let mut result: Vec<RecordBatch> = Vec::new();
            let verify_ms = median_ms(ITERS, || {
                result = rt
                    .block_on(verify(spec.sql, &commitment_paths, &proof_path, threads))
                    .unwrap_or_else(|err| panic!("baseline verify {label} q{q}: {err}"));
            });
            let mut expected: Vec<RecordBatch> = Vec::new();
            let execute_ms = median_ms(ITERS, || {
                expected = rt.block_on(execute(spec.sql, &query_tables, threads));
            });
            check_result(spec.sql, &expected, &result);
            println!(
                "query sf={sf} variant={label} q={q} prove_ms={prove_ms:.4} proof_bytes={} verify_ms={verify_ms:.4} execute_ms={execute_ms:.4} result_rows={}",
                file_len(&proof_path),
                result.iter().map(RecordBatch::num_rows).sum::<usize>()
            );
        }
    }
}
