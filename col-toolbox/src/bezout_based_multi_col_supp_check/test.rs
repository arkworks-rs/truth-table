use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
#[allow(unused_imports)]
use ark_piop::to_field_vec;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    prover::ArgProver,
    structs::TrackerID,
    test_utils::test_prelude,
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::arrow::datatypes::{DataType, Field};
use indexmap::IndexMap;
use std::{collections::HashMap, sync::Arc, vec};

use crate::bezout_based_multi_col_supp_check::{
    BezoutMultiColSuppCheckPIOP, BezoutMultiColSuppCheckProverInput,
    BezoutMultiColSuppCheckVerifierInput,
};

#[test]
fn single_col_supp_check_is_complete() -> SnarkResult<()> {
    multi_col_supp_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 4, 2, 4], Fr)],
        None,
        Some(to_field_vec!([true, true, true, false], Fr)),
        DataType::UInt32,
    )?;

    multi_col_supp_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 4, 2, 4], Fr)],
        None,
        Some(to_field_vec!([true, false, true, true], Fr)),
        DataType::UInt32,
    )?;

    multi_col_supp_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 4, 8, 4, 5, 8, 5, 8], Fr)],
        None,
        Some(to_field_vec!(
            [true, true, true, false, true, false, false, false],
            Fr
        )),
        DataType::UInt32,
    )?;
    multi_col_supp_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 4, 8, 4, 5, 8, 5, 8], Fr)],
        Some(to_field_vec!(
            [true, true, true, true, true, true, true, false],
            Fr
        )),
        Some(to_field_vec!(
            [true, true, true, false, true, false, false, false],
            Fr
        )),
        DataType::UInt32,
    )?;
    Ok(())
}

#[test]
fn single_col_supp_check_is_sound() -> SnarkResult<()> {
    multi_col_supp_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 4, 2, 4], Fr)],
        None,
        Some(to_field_vec!([true, true, true, true], Fr)),
        DataType::UInt32,
    )?;

    multi_col_supp_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 4, 8, 4, 5, 8, 5, 8], Fr)],
        None,
        Some(to_field_vec!(
            [true, true, true, false, true, false, false, true],
            Fr
        )),
        DataType::UInt32,
    )?;
    Ok(())
}

#[test]
fn multi_col_supp_check_is_complete() -> SnarkResult<()> {
    // multi_col_supp_check_test_helper::<DefaultSnarkBackend>(
    //     vec![
    //         to_field_vec!([1, 4, 2, 4], Fr),
    //         to_field_vec!([842, 439, 393, 439], Fr),
    //     ],
    //     vec![
    //         to_field_vec!([1, 2, 4, 4], Fr),
    //         to_field_vec!([842, 393, 439, 439], Fr),
    //     ],
    //     vec![
    //         to_field_vec!([2, 4, 4, 1], Fr),
    //         to_field_vec!([393, 439, 439, 842], Fr),
    //     ],
    //     to_field_vec!([1, 2, 1, 0], Fr),
    //     Some(vec![to_field_vec!([0, 0, 1, 0], Fr)]),
    //     None,
    //     Some(to_field_vec!([true, true, true, false], Fr)),
    //     Some(to_field_vec!([true, true, true, false], Fr)),
    //     Some(to_field_vec!([true, true, false, true], Fr)),
    //     DataType::UInt32,
    // )?;
    multi_col_supp_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([1, 4, 2, 4, 5, 8, 1, 1], Fr),
            to_field_vec!([842, 439, 393, 439, 673, 325, 294, 842], Fr),
        ],
        None,
        Some(to_field_vec!(
            [true, true, true, false, true, true, true, false],
            Fr
        )),
        DataType::UInt32,
    )?;
    Ok(())
}

pub(crate) fn multi_col_supp_check_test_helper<B: SnarkBackend>(
    cols_values: Vec<Vec<B::F>>,
    orig_activator: Option<Vec<B::F>>,
    supp_activator: Option<Vec<B::F>>,
    data_type: DataType,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<B>()?;
    let base_data_table = build_tracked_table(&mut prover, &cols_values, None, &data_type, "cols")?;
    let orig_activator_slice = orig_activator.as_deref();
    let supp_activator_slice = supp_activator.as_deref();
    let orig_table = table_with_activator(&mut prover, &base_data_table, orig_activator_slice)?;
    let supp_table = table_with_activator(&mut prover, &base_data_table, supp_activator_slice)?;

    let prover_input = BezoutMultiColSuppCheckProverInput {
        orig_tracked_table: orig_table.clone(),
        supp_tracked_table: supp_table.clone(),
    };

    BezoutMultiColSuppCheckPIOP::<B>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let mut oracle_cache: HashMap<TrackerID, TrackedOracle<B>> = HashMap::new();

    let orig_table_oracle = table_to_oracle(&mut verifier, &orig_table, &mut oracle_cache)?;
    let supp_table_oracle = table_to_oracle(&mut verifier, &supp_table, &mut oracle_cache)?;
    let verifier_input = BezoutMultiColSuppCheckVerifierInput {
        orig_tracked_table_oracle: orig_table_oracle,
        supp_tracked_table_oracle: supp_table_oracle,
    };

    BezoutMultiColSuppCheckPIOP::<B>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;
    Ok(())
}

pub(crate) fn multi_col_supp_check_soundness_helper<B: SnarkBackend>(
    cols_values: Vec<Vec<B::F>>,
    orig_activator: Option<Vec<B::F>>,
    supp_activator: Option<Vec<B::F>>,

    data_type: DataType,
) -> SnarkResult<()> {
    let result = multi_col_supp_check_test_helper::<B>(
        cols_values,
        orig_activator,
        supp_activator,
        data_type,
    );

    #[cfg(feature = "honest-prover")]
    {
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        match result {
            Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            ))) => Ok(()),
            Ok(_) => panic!("expected multi-column support check to fail under honest-prover mode"),
            Err(err) => Err(err),
        }
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        use ark_piop::{errors::SnarkError, verifier::errors::VerifierError};

        match result {
            Err(SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))) => Ok(()),
            Ok(_) => panic!("expected multi-column support check to fail"),
            Err(err) => Err(err),
        }
    }
}

fn table_with_activator<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    base_table: &TrackedTable<B>,
    activator: Option<&[B::F]>,
) -> SnarkResult<TrackedTable<B>> {
    match activator {
        Some(values) => {
            let log_size = base_table.log_size();
            let expected_len = 1usize << log_size;
            assert_eq!(
                values.len(),
                expected_len,
                "activator length ({}) must match table length ({expected_len})",
                values.len()
            );
            let activator_poly = prover
                .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(log_size, values))?;
            let mut tracked_polys = base_table.tracked_polys();
            tracked_polys.insert(
                Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false)),
                activator_poly,
            );
            Ok(TrackedTable::new(
                base_table.schema(),
                tracked_polys,
                log_size,
            ))
        }
        None => Ok(base_table.clone()),
    }
}

fn build_tracked_table<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    column_values: &[Vec<B::F>],
    shared_activator: Option<&[B::F]>,
    data_type: &DataType,
    prefix: &str,
) -> SnarkResult<TrackedTable<B>> {
    assert!(
        !column_values.is_empty(),
        "tracked table must contain at least one column"
    );

    let len = column_values[0].len();
    assert!(len > 0, "column values must not be empty");
    assert!(
        len.is_power_of_two(),
        "column length must be a power of two (got {len})"
    );

    if let Some(activator) = shared_activator {
        assert_eq!(
            activator.len(),
            len,
            "shared activator length must match column length"
        );
    }

    let nv = len.trailing_zeros() as usize;
    let mut tracked_polys =
        IndexMap::with_capacity(column_values.len() + usize::from(shared_activator.is_some()));

    for (idx, values) in column_values.iter().enumerate() {
        assert_eq!(
            values.len(),
            len,
            "all columns must have identical number of rows"
        );
        let data_poly =
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, values))?;
        let field_ref = Arc::new(Field::new(
            format!("{prefix}_col_{idx}"),
            data_type.clone(),
            false,
        ));
        tracked_polys.insert(field_ref, data_poly);
    }

    if let Some(activator_values) = shared_activator {
        let activator_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, activator_values))?;
        tracked_polys.insert(
            Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false)),
            activator_poly,
        );
    }

    Ok(TrackedTable::new(None, tracked_polys, nv))
}

fn track_oracle_cached<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    id: TrackerID,
    cache: &mut HashMap<TrackerID, TrackedOracle<B>>,
) -> SnarkResult<TrackedOracle<B>> {
    if let Some(existing) = cache.get(&id) {
        return Ok(existing.clone());
    }
    let oracle = verifier.track_mv_com_by_id(id)?;
    cache.insert(id, oracle.clone());
    Ok(oracle)
}

fn table_to_oracle<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    table: &TrackedTable<B>,
    cache: &mut HashMap<TrackerID, TrackedOracle<B>>,
) -> SnarkResult<TrackedTableOracle<B>> {
    let mut tracked_oracles = IndexMap::with_capacity(table.num_total_tracked_cols());
    for (field_ref, poly) in table.tracked_polys_iter() {
        let oracle = track_oracle_cached(verifier, poly.id(), cache)?;
        tracked_oracles.insert(field_ref.clone(), oracle);
    }
    Ok(TrackedTableOracle::new(
        table.schema(),
        tracked_oracles,
        table.log_size(),
    ))
}
