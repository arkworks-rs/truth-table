// use std::{fmt, path::PathBuf, sync::OnceLock};

// use ark_piop::test_utils::init_tracing_for_tests;
// use divan::black_box;
// use exec::{
//     prove::{
//         PreparedProverArtifacts, build_proof_from_artifacts, prepare_prover_artifacts_blocking,
//     },
//     test_utils::{resolve_key_paths, resolve_oracle_path_blocking},
// };
// use tpch_data::{bench_data_path, query_spec};

// #[derive(Clone, Copy, Debug)]
// struct BenchQuery {
//     name: &'static str,
//     query: &'static str,
//     tables: &'static [&'static str],
// }

// impl fmt::Display for BenchQuery {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{}", self.name)
//     }
// }

// fn prover_bench_queries() -> &'static [BenchQuery] {
//     static QUERIES: OnceLock<&'static [BenchQuery]> = OnceLock::new();
//     QUERIES.get_or_init(|| {
//         let tpch = query_spec(1);
//         let queries = vec![
//             BenchQuery {
//                 name: "tpch_q1",
//                 query: tpch.sql,
//                 tables: tpch.tables,
//             },
//             // BenchQuery {
//             //     name: "lineitem_dummy",
//             //     query: DUMMY_QUERY,
//             //     tables: DUMMY_TABLES,
//             // },
//         ];
//         Box::leak(queries.into_boxed_slice())
//     })
// }

// #[derive(Debug)]
// struct ProverBenchInputs {
//     spec: BenchQuery,
//     parquet_paths: Vec<PathBuf>,
//     oracle_paths: Vec<PathBuf>,
//     pk_path: PathBuf,
// }

// struct ProverBenchIteration {
//     artifacts: PreparedProverArtifacts,
// }

// fn prepare_prover_inputs(spec: BenchQuery) -> ProverBenchInputs {
//     assert!(
//         !spec.tables.is_empty(),
//         "bench queries must reference at least one table"
//     );
//     let (pk_path, _) = resolve_key_paths(exec::setup::DEFAULT_BENCH_LOG_SIZE)
//         .expect("resolve proving/verifying keys");

//     let parquet_paths = spec
//         .tables
//         .iter()
//         .map(|table| parquet_path_for_table(table))
//         .collect::<Vec<_>>();

//     let oracle_paths = parquet_paths
//         .iter()
//         .map(|parquet_path| {
//             resolve_oracle_path_blocking(parquet_path, &pk_path)
//                 .expect("resolve oracle path for bench")
//         })
//         .collect::<Vec<_>>();

//     ProverBenchInputs {
//         spec,
//         parquet_paths,
//         oracle_paths,
//         pk_path,
//     }
// }

// fn prepare_iteration_state(inputs: ProverBenchInputs) -> ProverBenchIteration {
//     let artifacts = prepare_prover_artifacts_blocking(
//         inputs.spec.query,
//         &inputs.parquet_paths,
//         &inputs.oracle_paths,
//         Some(inputs.pk_path.as_path()),
//     )
//     .expect("prepare prover artifacts for benchmark");

//     ProverBenchIteration { artifacts }
// }

// #[divan::bench(args = prover_bench_queries(), max_time = 1)]
// fn prove_command(bencher: divan::Bencher, spec: BenchQuery) {
//     bencher
//         .with_inputs(move || prepare_iteration_state(prepare_prover_inputs(spec)))
//         .bench_local_values(run_prove_iteration);
// }

// fn run_prove_iteration(iteration: ProverBenchIteration) {
//     let proof = build_proof_from_artifacts(iteration.artifacts)
//         .expect("execute prove backend for benchmark");

//     black_box(proof);
// }

// fn parquet_path_for_table(table: &str) -> PathBuf {
//     let path = bench_data_path(format!("{table}.parquet"));
//     assert!(
//         path.exists(),
//         "missing bench parquet {}. Run `cargo run --bin download-data --package tpch-data` to fetch it.",
//         path.display()
//     );
//     path
// }

// fn main() {
//     init_tracing_for_tests();
//     divan::main();
// }
