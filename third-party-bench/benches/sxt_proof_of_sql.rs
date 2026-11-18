//! PoSQL (HyperKZG) on the micro queries it supports. Its runner builds the
//! tables itself; the column override hands it `micro::table`'s data, so it
//! proves over the same rows as the other systems.

use std::path::Path;

use proof_of_sql::base::database::ColumnType;
use proof_of_sql_benchlib::{
    BenchOptions, HyperKzgBenchScheme, QueryEntry, TableDefinition, run_bench_with_scheme,
};
use tt_third_party_bench::micro;

const BENCH_ITERS: usize = 1;
const BENCH_PPOT_PATH: Option<&str> = None;

fn entry(query: &micro::MicroQuery) -> QueryEntry {
    let tables = query
        .tables
        .iter()
        .map(|&name| TableDefinition {
            name,
            columns: micro::table(name, 1)
                .into_iter()
                .map(|(column, _)| (column, ColumnType::BigInt, None))
                .collect(),
        })
        .collect();
    let sql: &'static str = Box::leak(micro::sql(query, query.tables).into_boxed_str());
    // PoSQL's runner gives each table of a query titled "Join" half of
    // `table_size` and sizes the setup to all of it, which a join's output needs.
    let title = if query.tables.len() > 1 {
        "Join"
    } else {
        query.name
    };
    (title, sql, tables, vec![])
}

fn main() {
    let ppot_path = BENCH_PPOT_PATH.filter(|path| Path::new(path).exists());
    let pows = micro::table_pows();
    println!("iterations: {BENCH_ITERS}");
    println!("table_sizes: {pows:?}");

    for pow in pows {
        let table_size = 1usize << pow;
        println!("table_size: {table_size}");
        for query in micro::QUERIES
            .iter()
            .filter(|q| q.posql && micro::selected(q))
        {
            let options = BenchOptions {
                iterations: BENCH_ITERS,
                table_size: table_size * query.tables.len(),
                rand_seed: Some(7),
                parquet_output_dir: None,
                #[allow(deprecated)]
                parquet_dir: None,
                column_override: Some(micro::column),
            };
            let output = run_bench_with_scheme::<_, HyperKzgBenchScheme>(
                &[entry(query)],
                &options,
                ppot_path.map(Path::new),
            )
            .expect("benchmark should run");

            for result in &output.results {
                println!("pow: {pow} query: {}", query.name);
                println!("setup_ms: {:.3}", result.setup_ms);
                println!("pk_bytes: {}", result.pk_bytes);
                println!("vk_bytes: {}", result.vk_bytes);
                println!("commit_ms: {:.3}", result.commit_ms);
                println!("commitment_bytes: {}", result.commitment_bytes);
                println!("prove_ms: {:.3}", result.generate_proof_ms);
                println!("proof_bytes: {}", result.proof_bytes);
                println!("verify_ms: {:.3}", result.verify_proof_ms);
                println!("result_rows: {}", result.num_query_results);
                println!("----------------------------------------");
            }
            assert!(output.results.len() >= BENCH_ITERS);
        }
    }
}
