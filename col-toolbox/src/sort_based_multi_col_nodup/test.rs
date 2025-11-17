use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    prover::ArgProver,
    structs::TrackerID,
    test_utils::test_prelude,
    to_field_vec,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::arrow::datatypes::{DataType, Field};
use indexmap::IndexMap;
use std::{collections::HashMap, sync::Arc};

use super::{
    SortBasedMultiNoDup, SortBasedMultiNoDupProverInput, SortBasedMultiNoDupVerifierInput,
};

#[test]
fn sort_based_single_no_dup_is_complete() -> SnarkResult<()> {
    sort_based_multi_no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([3, 1, 2, 4], Fr)],
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        None,
        DataType::UInt32,
    )?;

    sort_based_multi_no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([4, 2, 3, 1], Fr)],
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        to_field_vec!([1, 1, 1, 1], Fr).into(),
        to_field_vec!([1, 1, 1, 1], Fr).into(),
        to_field_vec!([1, 1, 1, 1], Fr).into(),
        DataType::UInt32,
    )?;

    sort_based_multi_no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8], Fr)],
        vec![to_field_vec!([1, 2, 3, 5, 6, 8, 4, 7], Fr)],
        None,
        vec![to_field_vec!([2, 3, 5, 6, 8, 4, 7, 1], Fr)],
        to_field_vec!([1, 1, 1, 0, 1, 1, 0, 1], Fr).into(),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr).into(),
        to_field_vec!([1, 1, 1, 1, 1, 0, 0, 1], Fr).into(),
        DataType::UInt32,
    )?;

    Ok(())
}

#[test]
fn sort_based_single_no_dup_is_sound() -> SnarkResult<()> {
    sort_based_multi_no_dup_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([3, 4, 2, 4], Fr)],
        vec![to_field_vec!([4, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 4], Fr)],
        None,
        None,
        None,
        DataType::UInt32,
    )?;

    sort_based_multi_no_dup_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([3, 1, 3, 4], Fr)],
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        None,
        DataType::UInt32,
    )?;
    sort_based_multi_no_dup_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([3, 1, 3, 4], Fr)],
        vec![to_field_vec!([3, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        None,
        DataType::UInt32,
    )?;
    Ok(())
}
#[test]
fn sort_based_multi_no_dup_is_complete() -> SnarkResult<()> {
    sort_based_multi_no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([3, 1, 2, 4], Fr),
            to_field_vec!([6, 5, 8, 7], Fr),
        ],
        vec![
            to_field_vec!([1, 2, 3, 4], Fr),
            to_field_vec!([5, 8, 6, 7], Fr),
        ],
        Some(vec![to_field_vec!([0, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([2, 3, 4, 1], Fr),
            to_field_vec!([8, 6, 7, 5], Fr),
        ],
        None,
        None,
        None,
        DataType::UInt32,
    )?;

    sort_based_multi_no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([3, 1, 1, 4], Fr),
            to_field_vec!([6, 5, 8, 7], Fr),
        ],
        vec![
            to_field_vec!([1, 1, 3, 4], Fr),
            to_field_vec!([5, 8, 6, 7], Fr),
        ],
        Some(vec![to_field_vec!([1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([1, 3, 4, 1], Fr),
            to_field_vec!([8, 6, 7, 5], Fr),
        ],
        None,
        None,
        None,
        DataType::UInt32,
    )?;

    sort_based_multi_no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([3, 1, 1, 4, 9, 11, 4, 3], Fr),
            to_field_vec!([6, 5, 8, 7, 10, 12, 8, 1], Fr),
        ],
        vec![
            to_field_vec!([1, 1, 3, 3, 4, 4, 9, 11], Fr),
            to_field_vec!([5, 8, 1, 6, 7, 8, 10, 12], Fr),
        ],
        Some(vec![to_field_vec!([1, 0, 1, 0, 1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([1, 3, 3, 4, 4, 9, 11, 1], Fr),
            to_field_vec!([8, 1, 6, 7, 8, 10, 12, 5], Fr),
        ],
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr).into(),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr).into(),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr).into(),
        DataType::UInt32,
    )?;
    sort_based_multi_no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([3, 1, 1, 4, 9, 11, 4, 3], Fr),
            to_field_vec!([6, 5, 8, 7, 10, 12, 7, 1], Fr),
        ],
        vec![
            to_field_vec!([1, 1, 3, 3, 4, 9, 11, 4], Fr),
            to_field_vec!([5, 8, 1, 6, 7, 10, 12, 7], Fr),
        ],
        Some(vec![to_field_vec!([1, 0, 1, 0, 0, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([1, 3, 3, 4, 9, 11, 4, 1], Fr),
            to_field_vec!([8, 1, 6, 7, 10, 12, 7, 5], Fr),
        ],
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 1], Fr).into(),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr).into(),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 1], Fr).into(),
        DataType::UInt32,
    )?;
    Ok(())
}

#[test]
fn sort_based_multi_no_dup_is_sound() -> SnarkResult<()> {
    sort_based_multi_no_dup_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([3, 1, 3, 4], Fr),
            to_field_vec!([6, 5, 6, 7], Fr),
        ],
        vec![
            to_field_vec!([1, 3, 3, 4], Fr),
            to_field_vec!([5, 6, 6, 7], Fr),
        ],
        Some(vec![to_field_vec!([0, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([3, 3, 4, 1], Fr),
            to_field_vec!([6, 6, 7, 5], Fr),
        ],
        None,
        None,
        None,
        DataType::UInt32,
    )?;

    sort_based_multi_no_dup_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([3, 1, 1, 4], Fr),
            to_field_vec!([6, 5, 8, 7], Fr),
        ],
        vec![
            to_field_vec!([1, 1, 3, 4], Fr),
            to_field_vec!([5, 5, 6, 7], Fr),
        ],
        Some(vec![to_field_vec!([1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([1, 3, 4, 1], Fr),
            to_field_vec!([5, 6, 7, 5], Fr),
        ],
        None,
        None,
        None,
        DataType::UInt32,
    )?;

    sort_based_multi_no_dup_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([3, 1, 1, 4, 9, 11, 4, 3], Fr),
            to_field_vec!([6, 5, 8, 7, 10, 12, 7, 1], Fr),
        ],
        vec![
            to_field_vec!([1, 1, 3, 3, 4, 4, 9, 11], Fr),
            to_field_vec!([5, 8, 1, 6, 7, 7, 10, 12], Fr),
        ],
        Some(vec![to_field_vec!([1, 0, 1, 0, 1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([1, 3, 3, 4, 4, 9, 11, 1], Fr),
            to_field_vec!([8, 1, 6, 7, 7, 10, 12, 5], Fr),
        ],
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr).into(),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr).into(),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr).into(),
        DataType::UInt32,
    )?;

    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn sort_based_multi_no_dup_test_helper<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    tracked_cols_values: Vec<Vec<F>>,
    sorted_cols_values: Vec<Vec<F>>,
    tie_indicator_values: Option<Vec<Vec<F>>>,
    shift_values: Vec<Vec<F>>,
    tracked_activator: Option<Vec<F>>,
    sorted_activator: Option<Vec<F>>,
    shift_activator: Option<Vec<F>>,
    data_type: DataType,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<F, MvPCS, UvPCS>()?;

    let tracked_activator_slice = tracked_activator.as_deref();
    let sorted_activator_slice = sorted_activator.as_deref();
    let shift_activator_slice = shift_activator.as_deref();

    let tracked_table = build_tracked_table(
        &mut prover,
        &tracked_cols_values,
        tracked_activator_slice,
        &data_type,
        "tracked",
    )?;
    let contig_sorted_table = build_tracked_table(
        &mut prover,
        &sorted_cols_values,
        sorted_activator_slice,
        &data_type,
        "sorted",
    )?;
    let shift_tracked_table = build_tracked_table(
        &mut prover,
        &shift_values,
        shift_activator_slice,
        &data_type,
        "shift",
    )?;
    let tracked_table_for_verifier = tracked_table.clone();
    let contig_sorted_table_for_verifier = contig_sorted_table.clone();
    let shift_table_for_verifier = shift_tracked_table.clone();

    let row_len = tracked_cols_values
        .first()
        .map(|col| col.len())
        .expect("tracked columns must contain data");
    let tie_indicator_tracked_table = match tie_indicator_values {
        Some(values) => {
            assert!(
                !values.is_empty(),
                "tie indicator columns cannot be empty when provided"
            );
            for column in &values {
                assert_eq!(
                    column.len(),
                    row_len,
                    "tie indicator column length must match tracked column length"
                );
            }
            Some(build_tracked_table(
                &mut prover,
                &values,
                tracked_activator_slice,
                &DataType::Boolean,
                "tie_indicator",
            )?)
        }
        None => None,
    };
    let tie_indicator_table_for_verifier = tie_indicator_tracked_table.clone();

    let prover_input = SortBasedMultiNoDupProverInput {
        tracked_table,
        contig_lex_sorted_tracked_table: contig_sorted_table,
        tie_indicator_tracked_table,
        shift_tracked_table,
    };

    SortBasedMultiNoDup::<F, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let mut oracle_cache: HashMap<TrackerID, TrackedOracle<F, MvPCS, UvPCS>> = HashMap::new();

    let tracked_table_oracle =
        table_to_oracle(&mut verifier, tracked_table_for_verifier, &mut oracle_cache)?;
    let contig_sorted_table_oracle = table_to_oracle(
        &mut verifier,
        contig_sorted_table_for_verifier,
        &mut oracle_cache,
    )?;
    let shift_tracked_table_oracle =
        table_to_oracle(&mut verifier, shift_table_for_verifier, &mut oracle_cache)?;
    let tie_indicator_tracked_table_oracle = tie_indicator_table_for_verifier
        .map(|table| table_to_oracle(&mut verifier, table, &mut oracle_cache))
        .transpose()?;

    let verifier_input = SortBasedMultiNoDupVerifierInput {
        tracked_table_oracle,
        contig_lex_sorted_tracked_table_oracle: contig_sorted_table_oracle,
        tie_indicator_tracked_table_oracle,
        shift_tracked_table_oracle,
    };

    SortBasedMultiNoDup::<F, MvPCS, UvPCS>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn sort_based_multi_no_dup_soundness_helper<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    tracked_cols_values: Vec<Vec<F>>,
    sorted_cols_values: Vec<Vec<F>>,
    tie_indicator_values: Option<Vec<Vec<F>>>,
    shift_values: Vec<Vec<F>>,
    tracked_activator: Option<Vec<F>>,
    sorted_activator: Option<Vec<F>>,
    shift_activator: Option<Vec<F>>,
    data_type: DataType,
) -> SnarkResult<()> {
    let result = sort_based_multi_no_dup_test_helper::<F, MvPCS, UvPCS>(
        tracked_cols_values,
        sorted_cols_values,
        tie_indicator_values,
        shift_values,
        tracked_activator,
        sorted_activator,
        shift_activator,
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
            Ok(_) => panic!(
                "expected sort-based multi-column no-dup check to fail under honest-prover mode"
            ),
            Err(err) => Err(err),
        }
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        use ark_piop::{errors::SnarkError, verifier::errors::VerifierError};

        match result {
            Err(SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))) => Ok(()),
            Ok(_) => panic!("expected sort-based multi-column no-dup check to fail"),
            Err(err) => Err(err),
        }
    }
}

fn track_oracle_cached<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    id: TrackerID,
    cache: &mut HashMap<TrackerID, TrackedOracle<F, MvPCS, UvPCS>>,
) -> SnarkResult<TrackedOracle<F, MvPCS, UvPCS>> {
    if let Some(existing) = cache.get(&id) {
        return Ok(existing.clone());
    }
    let oracle = verifier.track_mv_com_by_id(id)?;
    cache.insert(id, oracle.clone());
    Ok(oracle)
}

fn build_tracked_table<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    prover: &mut ArgProver<F, MvPCS, UvPCS>,
    column_values: &[Vec<F>],
    shared_activator: Option<&[F]>,
    data_type: &DataType,
    prefix: &str,
) -> SnarkResult<TrackedTable<F, MvPCS, UvPCS>> {
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
        IndexMap::with_capacity(column_values.len() + (shared_activator.is_some() as usize));

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

fn table_to_oracle<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    table: TrackedTable<F, MvPCS, UvPCS>,
    cache: &mut HashMap<TrackerID, TrackedOracle<F, MvPCS, UvPCS>>,
) -> SnarkResult<TrackedTableOracle<F, MvPCS, UvPCS>> {
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
