use std::path::{Path, PathBuf};

use proof_of_sql::{
    base::commitment::InnerProductProof,
    proof_primitive::hyperkzg::HyperKZGCommitmentEvaluationProof,
};
use proof_of_sql_benchlib::{
    get_query, run_bench_with_scheme, BenchOptions, HyperKzgBenchScheme, InnerProductBenchScheme,
};

// Possible queries: Filter, Complex Filter, Arithmetic, Group By, Aggregate, Boolean Filter,
// Large Column Set, Complex Condition, Sum Count, Coin, Join, Union All, Limit Offset, Not.
const BENCH_QUERY: &str = "Filter";
const BENCH_ITERS: usize = 1;
const BENCH_TABLE_POW_MIN: u32 = 10;
const BENCH_TABLE_POW_MAX: u32 = 20;
const BENCH_PARQUET_DIR: Option<&str> = Some("artifact");
const BENCH_PPOT_PATH: Option<&str> = None;
const BENCH_SCHEME: BenchScheme = BenchScheme::HyperKZG;

#[derive(Debug, Clone, Copy)]
enum BenchScheme {
    HyperKZG,
    InnerProduct,
}

fn main() {
    let query_name = BENCH_QUERY.to_string();
    let iterations = BENCH_ITERS;
    let ppot_path = BENCH_PPOT_PATH.filter(|path| Path::new(path).exists());

    let query = get_query(&query_name).expect("query exists");

    if BENCH_PPOT_PATH.is_some() && ppot_path.is_none() {
        println!(
            "BENCH_PPOT_PATH was set but file does not exist; falling back to generated setup."
        );
    }

    println!("query: {query_name}");
    println!("iterations: {iterations}");
    println!(
        "table_sizes: 2^{}..=2^{}",
        BENCH_TABLE_POW_MIN, BENCH_TABLE_POW_MAX
    );

    for pow in BENCH_TABLE_POW_MIN..=BENCH_TABLE_POW_MAX {
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
                "{},{},{},{},{},{}",
                result.commitment_scheme,
                result.query,
                result.table_size,
                result.generate_proof_ms,
                result.verify_proof_ms,
                result.iteration
            );
            println!(
                "prove_ms: {} verify_ms: {} iteration: {}",
                result.generate_proof_ms, result.verify_proof_ms, result.iteration
            );
            println!("Number of query results: {}", result.num_query_results);
        }

        assert!(!output.results.is_empty());
        assert!(output.results.len() >= iterations);
        println!("----------------------------------------");
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
