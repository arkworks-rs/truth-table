//! The no-proof baseline (`tt_third_party_bench::baseline`) on the micro
//! queries, over the raw bench parquets rather than the preprocessed ones.

use std::path::{Path, PathBuf};

use datafusion::arrow::array::RecordBatch;
use tt_third_party_bench::baseline::{
    Table, check_result, commit, file_len, load_parquet, median_ms, prove, store,
    threads_and_runtime, verify,
};

const PARQUET_DIR: &str = "artifact";

// Keep in sync with the matching arrays in the other benches.
const TABLE_POWS: &[u32] = &[16, 17, 18, 19];

const ITERS: usize = 5;

struct QuerySpec {
    name: &'static str,
    dir: &'static str,
    tables: &'static [&'static str],
    sql: &'static str,
}

// The SQL of `truth_table.rs`. `{table1}`/`{table2}` (or `{table}`) are
// replaced with the parquet file stems.
const QUERIES: &[QuerySpec] = &[
    QuerySpec {
        name: "filter",
        dir: "filter",
        tables: &["bench_table"],
        sql: "SELECT a, b, c, d FROM {table} WHERE a = 1 AND b = 2",
    },
    QuerySpec {
        name: "aggregate_count",
        dir: "aggregate_count",
        tables: &["bench_table"],
        sql: "SELECT count(b) FROM {table}",
    },
    QuerySpec {
        name: "join",
        dir: "Join",
        tables: &["bench_table", "bench_table_2"],
        sql: "SELECT {table1}.a AS a1, {table2}.a AS a2 FROM {table1}, {table2} WHERE {table1}.a = {table2}.a",
    },
    QuerySpec {
        name: "join_pk_fk",
        dir: "Join_PK_FK",
        tables: &["bench_table", "bench_table_2"],
        sql: "SELECT {table1}.a AS a1, {table2}.a_fk AS a2 FROM {table1}, {table2} WHERE {table1}.a = {table2}.a_fk",
    },
    QuerySpec {
        name: "limit_offset",
        dir: "Limit_Offset",
        tables: &["bench_table"],
        sql: "SELECT \"column\" FROM {table} LIMIT 10",
    },
];

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (threads, rt) = threads_and_runtime();

    println!("threads: {threads}");
    println!("iterations: {ITERS}");
    println!("table_sizes: {TABLE_POWS:?}");

    for &pow in TABLE_POWS {
        for query in QUERIES {
            let query_dir = bench_root
                .join(PARQUET_DIR)
                .join(format!("size_{pow}"))
                .join(query.dir);
            let tables: Vec<Table> = query
                .tables
                .iter()
                .map(|prefix| {
                    let name = format!("{prefix}_{pow}");
                    let batch = load_parquet(&query_dir.join(format!("{name}.parquet")));
                    Table::new(name, batch, &query_dir)
                })
                .collect();
            let table_refs: Vec<&Table> = tables.iter().collect();
            let sql = query
                .sql
                .replace("{table}", &tables[0].name)
                .replace("{table1}", &tables[0].name)
                .replace("{table2}", &tables[tables.len() - 1].name);
            let proof_path = query_dir.join("baseline.proof");
            let commitment_paths: Vec<PathBuf> =
                tables.iter().map(|t| t.commitment_path.clone()).collect();
            let rows: Vec<String> = tables
                .iter()
                .map(|t| t.batch.num_rows().to_string())
                .collect();
            println!("pow: {pow} query: {} rows: {}", query.name, rows.join(","));

            let commit_ms = median_ms(ITERS, || {
                for table in &tables {
                    commit(table);
                }
            });
            for table in &tables {
                let (commitment, blobs) = commit(table);
                store(table, &commitment, blobs);
            }
            let commitment_bytes: u64 = commitment_paths.iter().map(|p| file_len(p)).sum();

            let prove_ms = median_ms(ITERS, || {
                rt.block_on(prove(&sql, &table_refs, &proof_path));
            });

            let mut result: Vec<RecordBatch> = Vec::new();
            let verify_ms = median_ms(ITERS, || {
                result = rt
                    .block_on(verify(&sql, &commitment_paths, &proof_path, threads))
                    .expect("baseline verify");
            });
            rt.block_on(check_result(&sql, &table_refs, threads, &result));
            let result_rows: usize = result.iter().map(RecordBatch::num_rows).sum();

            println!("commit_ms: {commit_ms:.4}");
            println!("commitment_bytes: {commitment_bytes}");
            println!("prove_ms: {prove_ms:.4}");
            println!("proof_bytes: {}", file_len(&proof_path));
            println!("verify_ms: {verify_ms:.4}");
            println!("result_rows: {result_rows}");
            println!("----------------------------------------");
        }
    }
}
