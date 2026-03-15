use std::path::{Path, PathBuf};

use proof_of_sql::{
    base::commitment::InnerProductProof,
    proof_primitive::hyperkzg::HyperKZGCommitmentEvaluationProof,
};
use proof_of_sql::base::database::{ColumnType, LiteralValue};
use proof_of_sql_benchlib::{
    get_query, run_bench_with_scheme, BenchOptions, HyperKzgBenchScheme, InnerProductBenchScheme,
    QueryEntry, TableDefinition,
};

// Possible queries: Filter, Complex Filter, Arithmetic, Group By, Aggregate, Boolean Filter,
// Large Column Set, Complex Condition, Sum Count, Coin, Join, Union All, Limit Offset, Not.
const BENCH_ITERS: usize = 1;
const BENCH_TABLE_POWS: &[u32] = &[16, 17, 18, 19];
const BENCH_PARQUET_DIR: Option<&str> = Some("artifact");
const BENCH_PPOT_PATH: Option<&str> = None;
const BENCH_SCHEME: BenchScheme = BenchScheme::HyperKZG;

#[derive(Debug, Clone, Copy)]
enum BenchScheme {
    HyperKZG,
    InnerProduct,
}

fn custom_queries() -> Vec<QueryEntry> {
    let mut queries = Vec::new();
    if let Some(join) = get_query("Join") {
        queries.push(join);
    }
    if let Some(limit_offset) = get_query("Limit Offset") {
        queries.push(limit_offset);
    }

    let table = TableDefinition {
        name: "bench_table",
        columns: vec![
            (
                "a",
                ColumnType::BigInt,
                Some(|size| (size / 10).max(10) as i64),
            ),
            (
                "b",
                ColumnType::BigInt,
                Some(|size| (size / 10).max(10) as i64),
            ),
            (
                "c",
                ColumnType::BigInt,
                Some(|size| (size / 10).max(10) as i64),
            ),
            (
                "d",
                ColumnType::BigInt,
                Some(|size| (size / 10).max(10) as i64),
            ),
        ],
    };

    queries.push((
        "filter",
        "SELECT * FROM bench_table WHERE a = $1 AND b = $2;",
        vec![table.clone()],
        vec![LiteralValue::BigInt(1), LiteralValue::BigInt(2)],
    ));

    let agg_table = TableDefinition {
        name: "bench_table",
        columns: vec![
            (
                "a",
                ColumnType::BigInt,
                Some(|size| (size / 10).max(10) as i64),
            ),
            (
                "b",
                ColumnType::BigInt,
                Some(|size| (size / 10).max(10) as i64),
            ),
        ],
    };

    queries.push((
        "aggregate_count",
        "SELECT COUNT(b) FROM bench_table;",
        vec![agg_table.clone()],
        vec![],
    ));
    queries
}

fn main() {
    // SAFETY: we set the environment variable once at process startup,
    // before any benchmark work or threads are spawned.
    unsafe {
        std::env::set_var("BLITZAR_BACKEND", "cpu");
    }
    println!("BLITZAR_BACKEND=cpu");

    let iterations = BENCH_ITERS;
    let ppot_path = BENCH_PPOT_PATH.filter(|path| Path::new(path).exists());

    if BENCH_PPOT_PATH.is_some() && ppot_path.is_none() {
        println!(
            "BENCH_PPOT_PATH was set but file does not exist; falling back to generated setup."
        );
    }
    println!("iterations: {iterations}");
    println!("table_sizes: {:?}", BENCH_TABLE_POWS);

    let queries = custom_queries();
    for &pow in BENCH_TABLE_POWS {
        let table_size = 1usize << pow;
        let parquet_dir = BENCH_PARQUET_DIR.map(|dir| format!("{dir}/size_{pow}"));
        let options = BenchOptions {
            iterations,
            table_size,
            rand_seed: Some(7),
            parquet_output_dir: parquet_dir.clone().map(Into::into),
            #[allow(deprecated)]
            parquet_dir: None,
        };

        println!("table_size: {}", table_size);
        if let Some(dir) = &parquet_dir {
            println!("parquet_dir: {dir}");
        }

        for query in &queries {
            let output = match BENCH_SCHEME {
                BenchScheme::HyperKZG => {
                    run_bench_with_scheme::<HyperKZGCommitmentEvaluationProof, HyperKzgBenchScheme>(
                        &[query.clone()],
                        &options,
                        ppot_path.as_ref().map(|path| path.as_ref()),
                    )
                }
                BenchScheme::InnerProduct => {
                    run_bench_with_scheme::<InnerProductProof, InnerProductBenchScheme>(
                        &[query.clone()],
                        &options,
                        ppot_path.as_ref().map(|path| path.as_ref()),
                    )
                }
            }
            .expect("benchmark should run");

            let renamed = rename_parquet_outputs(&output.parquet_paths, pow);
            if renamed.is_empty() {
                println!("parquet: none");
            } else {
                for path in &renamed {
                    println!("parquet: {}", path.display());
                }
            }

            for result in &output.results {
                println!(
                    "{},{},{},{},{},{},{}",
                    result.commitment_scheme,
                    result.query,
                    result.table_size,
                    result.generate_proof_ms,
                    result.verify_proof_ms,
                    result.proof_bytes,
                    result.iteration
                );
                println!(
                    "prove_ms: {} verify_ms: {} proof_bytes: {} iteration: {}",
                    result.generate_proof_ms,
                    result.verify_proof_ms,
                    result.proof_bytes,
                    result.iteration
                );
                println!("Number of query results: {}", result.num_query_results);
            }

            assert!(!output.results.is_empty());
            assert!(output.results.len() >= iterations);
            println!("----------------------------------------");
        }
    }
}

fn rename_parquet_outputs(paths: &[PathBuf], pow: u32) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for path in paths {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(parent) = path.parent() else {
            continue;
        };
        let new_name = format!("{stem}_{pow}.parquet");
        let new_path = parent.join(new_name);
        if let Err(err) = std::fs::rename(path, &new_path) {
            eprintln!(
                "failed to rename {} -> {}: {err}",
                path.display(),
                new_path.display()
            );
            out.push(path.to_path_buf());
        } else {
            out.push(new_path);
        }
    }
    out
}
