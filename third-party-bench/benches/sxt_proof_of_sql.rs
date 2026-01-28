use std::path::Path;
use proof_of_sql_benchlib::{
    get_query, run_bench_with_scheme, BenchOptions, HyperKzgBenchScheme,
};
use proof_of_sql::proof_primitive::hyperkzg::HyperKZGCommitmentEvaluationProof;

const BENCH_QUERY: &str = "Filter";
const BENCH_ITERS: usize = 1;
const BENCH_TABLE_SIZE: usize = 100000;
const BENCH_PARQUET_DIR: Option<&str> = None;
const BENCH_PPOT_PATH: Option<&str> = None;

fn main() {
    let query_name = BENCH_QUERY.to_string();
    let iterations = BENCH_ITERS;
    let table_size = BENCH_TABLE_SIZE;
    let parquet_dir = BENCH_PARQUET_DIR.map(str::to_string);
    let ppot_path = BENCH_PPOT_PATH.filter(|path| Path::new(path).exists());

    let query = get_query(&query_name).expect("query exists");
    let options = BenchOptions {
        iterations,
        table_size,
        rand_seed: Some(7),
        parquet_output_dir: parquet_dir.clone().map(Into::into),
        parquet_dir: None,
    };

    if BENCH_PPOT_PATH.is_some() && ppot_path.is_none() {
        println!(
            "BENCH_PPOT_PATH was set but file does not exist; falling back to generated setup."
        );
    }

    println!("query: {query_name}");
    println!("iterations: {iterations}");
    println!("table_size: {table_size}");
    if let Some(dir) = &parquet_dir {
        println!("parquet_dir: {dir}");
    }

    let output = run_bench_with_scheme::<HyperKZGCommitmentEvaluationProof, HyperKzgBenchScheme>(
        &[query],
        &options,
        ppot_path.as_ref().map(|path| path.as_ref()),
    )
    .expect("benchmark should run");

    if output.parquet_paths.is_empty() {
        println!("parquet: none");
    } else {
        for path in &output.parquet_paths {
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
}
