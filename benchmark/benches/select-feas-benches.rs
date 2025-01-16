// // use criterion::{criterion_group, criterion_main, Criterion};

// // fn my_function(n: u64) -> u64 {
// //     (0..n).sum()
// // }

// // fn criterion_benchmark(c: &mut Criterion) {
// //     c.bench_function("sum", |b| b.iter(|| my_function(1000)));
// // }

// // criterion_group!(benches, criterion_benchmark);
// // criterion_main!(benches);

// use ark_bls12_381::{Bls12_381, Fr};
// use ark_poly::{domain::radix2::Elements, DenseMultilinearExtension};
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use ark_std::{end_timer, log2, rand::Rng, start_timer, test_rng, One, Zero};
// use datafusion::{
//     arrow::{
//         self,
//         array::{AsArray, Int32Array, RecordBatch},
//         datatypes::Date32Type,
//     },
//     prelude::*,
// };
// use itertools::Itertools;
// use rayon::result;
// use std::{
//     any::Any,
//     borrow::BorrowMut,
//     fs::{read, File},
//     path::Path,
//     sync::Arc,
//     time::Instant,
// };
// use zk_sql::{
//     ra_toolbox,
//     subroutines::{MultilinearKzgPCS, MultilinearUniversalParams, PolynomialCommitmentScheme},
//     tracker::prelude::{Col, ColComm, ProverTrackerRef, VerifierTrackerRef},
//     col_toolbox::{self},
// };
// // https://elferherrera.github.io/arrow_guide/introduction.html

// // #[tokio::main]
// // async fn main(){
// //     sel_eq();
// // }

// // SELECT * FROM title WHERE production_year = 2006;
// #[tokio::main(flavor = "current_thread")]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // setting up the prover tracker and PCS parameters
//     const MAX_LOG_VAR: usize = 20;
//     let mut rng = test_rng();
//     let file_path = "srs";
//     let srs: MultilinearUniversalParams<Bls12_381> = if Path::new(file_path).exists() {
//         dbg!("File exists");
//         // The file exists; read and print its contents
//         let mut file = File::open(file_path)?;
//         let mut reader = std::io::BufReader::new(file);
//         MultilinearUniversalParams::<Bls12_381>::deserialize_uncompressed_unchecked(reader).unwrap()
//     } else {
//         dbg!("File does not exist");
//         // The file does not exist; create it and write some content
//         let mut file = File::create(file_path)?;
//         let mut writer = std::io::BufWriter::new(file);
//         let srs =
//             MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, MAX_LOG_VAR).unwrap();
//         srs.serialize_uncompressed(writer)?;
//         srs
//     };

//     let (prover_param, verifier_param) =
//         MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(MAX_LOG_VAR)).unwrap();
//     let mut prover_tracker_ref =
//         ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>::new_from_pcs_params(
//             prover_param,
//         );
//     // Fetching the full table from the Parquet file - Only numerical columns were
//     // selected for the test since we don't have an adapter
//     let ctx: SessionContext = SessionContext::new();
//     let full_df: DataFrame = ctx
//         .read_parquet(
//             "imdb_parquet/aka_title.parquet",
//             ParquetReadOptions::default(),
//         )
//         .await?;
//     let full_df: DataFrame = full_df.select_columns(&["production_year"])?;

//     // Tracking the multilinear extension of the columns
//     let full_results: Vec<RecordBatch> = full_df.collect().await?;


//     let mut production_year_field_vec =
//         full_results
//             .iter()
//             .fold(vec![], |mut acc, current_record_batch| {
//                 let current_batch_array: &Int32Array = current_record_batch
//                     .column_by_name("production_year")
//                     .unwrap()
//                     .as_primitive_opt()
//                     .unwrap();
//                 let current_batch_data: &arrow::buffer::ScalarBuffer<i32> =
//                     current_batch_array.values();
//                 acc.extend(current_batch_data.iter().map(|x| Fr::from(*x)));
//                 acc
//             });

//     let full_size = production_year_field_vec.len();

//     production_year_field_vec.extend(vec![
//         Fr::zero();
//         2_usize.pow(MAX_LOG_VAR as u32) - full_size
//     ]);
//     let production_year_field_vec_copy = production_year_field_vec.clone();
//     let production_year_poly =
//         DenseMultilinearExtension::from_evaluations_vec(MAX_LOG_VAR, production_year_field_vec);
//     let input_tracked_poly = prover_tracker_ref
//         .track_and_commit_poly(production_year_poly.clone())
//         .unwrap();

//     // Creating the activator polynomial - Every row is active at first
//     let mut activator_col: Vec<Fr> = vec![Fr::one(); full_size];
//     activator_col.extend(vec![
//         Fr::zero();
//         2_usize.pow(MAX_LOG_VAR as u32) - full_size
//     ]);

//     let activator_poly =
//         DenseMultilinearExtension::from_evaluations_vec(MAX_LOG_VAR, activator_col.clone());
//     let activator_tracked_poly = prover_tracker_ref
//         .track_and_commit_poly(activator_poly)
//         .unwrap();

//     // Start of the Query SELECT * FROM title WHERE production_year > 2006;
//     // Updating the activator
//     let timer = Instant::now();

//     let mut new_activator_col = vec![];
//     for production_year in production_year_field_vec_copy.iter() {
//         if *production_year == Fr::from(2006) {
//             new_activator_col.push(Fr::one());
//         } else {
//             new_activator_col.push(Fr::zero());
//         }
//     }

//     let new_activator_poly =
//         DenseMultilinearExtension::from_evaluations_vec(MAX_LOG_VAR, new_activator_col.clone());
//     let new_tracked_activator_poly = prover_tracker_ref
//         .track_and_commit_poly(new_activator_poly)
//         .unwrap();
//     let query_time = timer.elapsed();

//     assert_eq!(new_activator_col.len(), activator_col.len());
//     let output_tracked_poly = prover_tracker_ref
//         .track_and_commit_poly(production_year_poly)
//         .unwrap();
//     let input_col = Col::new(input_tracked_poly, activator_tracked_poly);
//     let output_col = Col::new(output_tracked_poly, new_tracked_activator_poly);
//     let timer = Instant::now();
//     ra_toolbox::select::eq::SelEqPIOP::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>::prove(
//         &mut prover_tracker_ref,
//         &input_col,
//         &output_col,
//         Fr::from(2006),
//     )
//     .unwrap();
//     let proof = prover_tracker_ref.compile_proof().unwrap();

//     let proving_time = timer.elapsed();

//     // set up verifier tracker, create subclaims, and verify IOPProofs
//     let mut verifier_tracker_ref: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
//         VerifierTrackerRef::new_from_pcs_params(verifier_param);
//     verifier_tracker_ref.set_compiled_proof(proof);   


//     let input_poly_com = verifier_tracker_ref.transfer_prover_comm(input_col.poly.id);

//     let input_selector_com = verifier_tracker_ref.transfer_prover_comm(input_col.selector.id);

//     let output_selector_com = verifier_tracker_ref.transfer_prover_comm(output_col.selector.id);

//     let output_poly_com = verifier_tracker_ref.transfer_prover_comm(output_col.poly.id);



//     let input_col_comm = ColComm::new(input_poly_com, input_selector_com, MAX_LOG_VAR);

//     let output_col_comm = ColComm::new(output_poly_com, output_selector_com, MAX_LOG_VAR);

//     let timer = Instant::now();
//     ra_toolbox::select::eq::SelEqPIOP::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>::verify(
//         &mut verifier_tracker_ref,
//         &input_col_comm,
//         &output_col_comm,
//         Fr::from(2006),
//     )
//     .unwrap();
//     verifier_tracker_ref.verify_claims().unwrap();
//     let verifier_time = timer.elapsed();

//     dbg!(query_time.as_millis());
//     dbg!(proving_time.as_millis());
//     dbg!(verifier_time.as_millis());

//     Ok(())
// }

// // Create a new branch
// // Commit the changes
// // Create pull request
