// use criterion::{criterion_group, criterion_main, Criterion};

// fn my_function(n: u64) -> u64 {
//     (0..n).sum()
// }

// fn criterion_benchmark(c: &mut Criterion) {
//     c.bench_function("sum", |b| b.iter(|| my_function(1000)));
// }

// criterion_group!(benches, criterion_benchmark);
// criterion_main!(benches);

use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::{domain::radix2::Elements, DenseMultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, log2, rand::Rng, start_timer, test_rng, One, Zero};
use datafusion::{
    arrow::{
        self,
        array::{AsArray, Int32Array, RecordBatch},
        datatypes::Date32Type,
    },
    prelude::*,
};
use itertools::Itertools;
use rayon::result;
use std::{
    borrow::BorrowMut,
    fs::{read, File},
    path::Path,
    sync::Arc,
    time::Instant,
};
use zk_sql::{
    subroutines::{MultilinearKzgPCS, MultilinearUniversalParams, PolynomialCommitmentScheme},
    tracker::prelude::ProverTrackerRef, zksql_poly_iop::{self, selector_valid::selector_valid::SelectorValidIOP},
};
// https://elferherrera.github.io/arrow_guide/introduction.html

// SELECT * FROM title WHERE production_year > 2006;
#[tokio::test]
async fn test() -> Result<(), Box<dyn std::error::Error>> {
    // setting up the prover tracker and PCS parameters

    const MAX_LOG_VAR: usize = 19;
    let mut rng = test_rng();
    let file_path = "srs";
    let srs: MultilinearUniversalParams<Bls12_381> = if Path::new(file_path).exists() {
        dbg!("File exists");
        // The file exists; read and print its contents
        let mut file = File::open(file_path)?;
        let mut reader = std::io::BufReader::new(file);
        MultilinearUniversalParams::<Bls12_381>::deserialize_uncompressed_unchecked(reader).unwrap()
    } else {
        dbg!("File does not exist");
        // The file does not exist; create it and write some content
        let mut file = File::create(file_path)?;
        let mut writer = std::io::BufWriter::new(file);
        let srs =
            MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, MAX_LOG_VAR).unwrap();
        srs.serialize_uncompressed(writer)?;
        srs
    };

    let (pcs_param, _) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(MAX_LOG_VAR)).unwrap();
    let mut prover_tracker_ref =
        ProverTrackerRef::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::new_from_pcs_params(pcs_param);

    // Fetching the full table from the Parquet file - Only numerical columns were
    // selected for the test since we don't have an adapter
    let ctx: SessionContext = SessionContext::new();
    let full_df: DataFrame = ctx
        .read_parquet(
            "imdb_parquet/aka_title.parquet",
            ParquetReadOptions::default(),
        )
        .await?;
    let full_df: DataFrame = full_df.select_columns(&["id", "movie_id", "production_year"])?;

    // Tracking the multilinear extension of the columns
    let full_results: Vec<RecordBatch> = full_df.collect().await?;

    let timer = Instant::now();

    let mut id_field_vec = full_results
        .iter()
        .fold(vec![], |mut acc, current_record_batch| {
            let current_batch_array: &Int32Array = current_record_batch
                .column_by_name("id")
                .unwrap()
                .as_primitive_opt()
                .unwrap();
            let current_batch_data: &arrow::buffer::ScalarBuffer<i32> =
                current_batch_array.values();
            acc.extend(current_batch_data.iter().map(|x| Fr::from(*x)));
            acc
        });

    let mut movie_id_field_vec =
        full_results
            .iter()
            .fold(vec![], |mut acc, current_record_batch| {
                let current_batch_array: &Int32Array = current_record_batch
                    .column_by_name("movie_id")
                    .unwrap()
                    .as_primitive_opt()
                    .unwrap();
                let current_batch_data: &arrow::buffer::ScalarBuffer<i32> =
                    current_batch_array.values();
                acc.extend(current_batch_data.iter().map(|x| Fr::from(*x)));
                acc
            });
    let mut production_year_field_vec =
        full_results
            .iter()
            .fold(vec![], |mut acc, current_record_batch| {
                let current_batch_array: &Int32Array = current_record_batch
                    .column_by_name("production_year")
                    .unwrap()
                    .as_primitive_opt()
                    .unwrap();
                let current_batch_data: &arrow::buffer::ScalarBuffer<i32> =
                    current_batch_array.values();
                acc.extend(current_batch_data.iter().map(|x| Fr::from(*x)));
                acc
            });

    let full_size = id_field_vec.len();

    id_field_vec.extend(vec![
        Fr::zero();
        2_usize.pow(MAX_LOG_VAR as u32) - full_size
    ]);

    movie_id_field_vec.extend(vec![
        Fr::zero();
        2_usize.pow(MAX_LOG_VAR as u32) - full_size
    ]);

    production_year_field_vec.extend(vec![
        Fr::zero();
        2_usize.pow(MAX_LOG_VAR as u32) - full_size
    ]);

    let id_poly = DenseMultilinearExtension::from_evaluations_vec(MAX_LOG_VAR, id_field_vec);
    let movie_id_poly =
        DenseMultilinearExtension::from_evaluations_vec(MAX_LOG_VAR, movie_id_field_vec);
    let production_year_poly =
        DenseMultilinearExtension::from_evaluations_vec(MAX_LOG_VAR, production_year_field_vec);
    let column_extension_time = timer.elapsed();

    // Creating the activator polynomial - Every row is active at first
    let timer = Instant::now();
    let mut activator_col: Vec<Fr> = vec![Fr::one(); full_size];
    activator_col.extend(vec![
        Fr::zero();
        2_usize.pow(MAX_LOG_VAR as u32) - full_size
    ]);
    let activator_poly =
        DenseMultilinearExtension::from_evaluations_vec(MAX_LOG_VAR, activator_col.clone());
    let activator_poly_time = timer.elapsed();

    // Start of the Query SELECT * FROM title WHERE production_year > 2006;
    // Updating the activator
    let timer = Instant::now();
    let mut production_year_int_vec: Vec<i32> =
        full_results
            .iter()
            .fold(vec![], |mut acc, current_record_batch| {
                let current_batch_array: &Int32Array = current_record_batch
                    .column_by_name("production_year")
                    .unwrap()
                    .as_primitive_opt()
                    .unwrap();
                let current_batch_data: &arrow::buffer::ScalarBuffer<i32> =
                    current_batch_array.values();
                acc.extend(current_batch_data.iter());
                acc
            });

    let mut new_activator_col = vec![];
    for production_year in production_year_int_vec.iter() {
        if *production_year <= 2006 {
            new_activator_col.push(Fr::zero());
        } else {
            new_activator_col.push(Fr::one());
        }
    }
    new_activator_col.extend(vec![
        Fr::zero();
        2_usize.pow(MAX_LOG_VAR as u32) - full_size
    ]);
    let new_activator_poly =
        DenseMultilinearExtension::from_evaluations_vec(MAX_LOG_VAR, new_activator_col.clone());
    let new_tracked_activator_poly = prover_tracker_ref.track_and_commit_poly(new_activator_poly).unwrap();
    let query_time = timer.elapsed();

    assert_eq!(new_activator_col.len(), activator_col.len());


    let timer = Instant::now(); 
    SelectorValidIOP::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::prove(
        &mut prover_tracker_ref,
        &new_tracked_activator_poly,
    );

    let valid_selector_time = timer.elapsed();

//1-positivie-original
// arithemtic comparison equaility

    dbg!(column_extension_time.as_millis());
    dbg!(activator_poly_time.as_millis());
    dbg!(query_time.as_millis());
    dbg!(valid_selector_time.as_millis());

    Ok(())
}

// Create a new branch
// Commit the changes
// Create pull request
