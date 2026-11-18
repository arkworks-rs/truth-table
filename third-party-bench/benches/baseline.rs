//! The no-proof baseline (`tt_third_party_bench::baseline`) on the micro
//! queries (`tt_third_party_bench::micro`), over the raw parquets rather than
//! TruthTable's preprocessed ones.
//! `execute_ms` is plain execution: the query on the full tables, unverified.
//! Commit and prove run once; verification and execution repeat for up to a
//! second, and their median is reported.

use std::path::{Path, PathBuf};

use datafusion::arrow::array::RecordBatch;
use tt_third_party_bench::{
    baseline::{
        Table, check_result, commit, execute, file_len, load_parquet, prove, store,
        threads_and_runtime, verify,
    },
    micro,
};

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (threads, rt) = threads_and_runtime();

    println!("threads: {threads}");
    let pows = micro::table_pows();
    println!("table_sizes: {pows:?}");

    for pow in pows {
        for query in micro::QUERIES.iter().filter(|q| micro::selected(q)) {
            let query_dir = micro::query_dir(bench_root, pow, query);
            let tables: Vec<Table> =
                micro::ensure_parquets(bench_root, pow, query, "_preprocessed")
                    .iter()
                    .map(|path| {
                        let name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .expect("stem")
                            .to_string();
                        Table::new(name, load_parquet(path), &query_dir)
                    })
                    .collect();
            let table_refs: Vec<&Table> = tables.iter().collect();
            let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();
            let sql = micro::sql(query, &names);
            let proof_path = query_dir.join("baseline.proof");
            let commitment_paths: Vec<PathBuf> =
                tables.iter().map(|t| t.commitment_path.clone()).collect();
            let rows: Vec<String> = tables
                .iter()
                .map(|t| t.batch.num_rows().to_string())
                .collect();
            println!("pow: {pow} query: {} rows: {}", query.name, rows.join(","));

            let start = std::time::Instant::now();
            let commitments: Vec<_> = tables.iter().map(commit).collect();
            let commit_ms = start.elapsed().as_secs_f64() * 1e3;
            for (table, (commitment, blobs)) in tables.iter().zip(commitments) {
                store(table, &commitment, blobs);
            }
            let commitment_bytes: u64 = commitment_paths.iter().map(|p| file_len(p)).sum();

            let start = std::time::Instant::now();
            rt.block_on(prove(&sql, &table_refs, &proof_path));
            let prove_ms = start.elapsed().as_secs_f64() * 1e3;

            let mut result: Vec<RecordBatch> = Vec::new();
            let verify_ms = micro::verify_median_ms(|| {
                result = rt
                    .block_on(verify(&sql, &commitment_paths, &proof_path, threads))
                    .expect("baseline verify");
            });
            let mut expected: Vec<RecordBatch> = Vec::new();
            let execute_ms = micro::verify_median_ms(|| {
                expected = rt.block_on(execute(&sql, &table_refs, threads));
            });
            check_result(&sql, &expected, &result);
            let result_rows: usize = result.iter().map(RecordBatch::num_rows).sum();

            println!("commit_ms: {commit_ms:.4}");
            println!("commitment_bytes: {commitment_bytes}");
            println!("prove_ms: {prove_ms:.4}");
            println!("proof_bytes: {}", file_len(&proof_path));
            println!("verify_ms: {verify_ms:.4}");
            println!("execute_ms: {execute_ms:.4}");
            println!("result_rows: {result_rows}");
            println!("----------------------------------------");
        }
    }
}
