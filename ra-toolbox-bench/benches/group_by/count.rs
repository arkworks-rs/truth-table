// use arithmetic::table::{ArithTable, ArithTableOracle};
// use ark_piop::{errors::SnarkResult, piop::PIOP, prover::Prover,
// verifier::Verifier}; use sql_toolbox::group_by::{
//     GroupByPIOP, GroupByProverInput, GroupByVerifierInput,
//     structs::{AggregationType, GroupByConfig},
// };

// use crate::{F, K, P, prepare_common_inputs};
// #[cfg(feature = "parallel")]
// use rayon::result;
// use tokio::runtime::Runtime;

// const INPUT_QUERY: &str = "SELECT PRODUCTION_YEAR, ID FROM
// 'parquets/title-sanitized.parquet'"; const OUTPUT_QUERY: &str = "SELECT
// PRODUCTION_YEAR, COUNT(ID) AS COUNT FROM 'parquets/title-sanitized.parquet'
// GROUP BY PRODUCTION_YEAR";

// // TODO: This function can be made generic on the PIOP type to avoid code
// // duplication. Change this accross all benchamrks.
// #[allow(clippy::type_complexity)]
// fn prepare_prover_inputs() -> (
//     Prover<F, P, K>,
//     Verifier<F, P, K>,
//     ArithTable<F, P, K>,
//     ArithTable<F, P, K>,
//     GroupByProverInput<F, P, K>,
// ) {
//     let rt = Runtime::new().unwrap();
//     rt.block_on(async {
//         let (prover, verifier, input_table, output_table) =
//             prepare_common_inputs(INPUT_QUERY, OUTPUT_QUERY).await;
//         let instr = GroupByConfig {
//             gpd_col_indices: vec![0],
//             agg_instr: vec![(1, AggregationType::Sum)],
//         };

//         let prover_input = GroupByProverInput {
//             input_table: input_table.clone(),
//             output_table: output_table.clone(),
//             instr: instr.clone(),
//         };

//         Ok::<_, anyhow::Error>((prover, verifier, input_table, output_table,
// prover_input))     })
//     .unwrap()
// }

// // ------------------------
// // Verifier Input Preparation
// // ------------------------

// fn prepare_verifier_inputs() -> (Verifier<F, P, K>, GroupByVerifierInput<F,
// P, K>) {     let (mut prover, mut verifier, input_table, output_table,
// prover_input) =         prepare_prover_inputs();
//     let rt = Runtime::new().unwrap();
//     rt.block_on(async {
//         // Generate proof
//         let _ = GroupByPIOP::<F, P, K>::prove(&mut prover,
// prover_input.clone());         let proof = prover.build_proof().unwrap();
//         verifier.set_proof(proof);

//         // Commit tables
//         let input_comm = ArithTableOracle::from(input_table, &mut verifier);
//         let output_comm = ArithTableOracle::from(output_table, &mut verifier);

//         let verifier_input = GroupByVerifierInput {
//             input_arith_table_oracle: input_comm,
//             output_arith_table_oracle: output_comm,
//             instr: prover_input.instr,
//         };

//         Ok::<_, anyhow::Error>((verifier, verifier_input))
//     })
//     .unwrap()
// }

// // ------------------------
// // Benchmarks
// // ------------------------

// #[divan::bench(sample_count = 1, sample_size = 1)]
// fn prove(bencher: divan::Bencher) {
//     bencher.with_inputs(prepare_prover_inputs).bench_values(
//         |(mut prover, _, _, _, prover_input)| {
//             let _ = GroupByPIOP::<F, P, K>::prove(&mut prover, prover_input);
//             let _ = prover.build_proof().unwrap();
//         },
//     );
// }

// // TODO: Change the following: Currently for each verification benchmark, a
// // seperate proving phase is done. It's bad and gives sigkill. Change the
// code // to do the proving once and clone the verifier for each verification
// // benchmark. Do this accross all benchamrks.
// #[divan::bench(max_time = 1)]
// fn verify(bencher: divan::Bencher) {
//     bencher
//         .with_inputs(prepare_verifier_inputs)
//         .bench_values(|(mut verifier, verifier_input)| {
//             let _: SnarkResult<()> = GroupByPIOP::<F, P, K>::verify(&mut
// verifier, verifier_input);             verifier.verify().unwrap();
//         });
// }
