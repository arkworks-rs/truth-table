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
use std::{collections::HashMap, sync::Arc};

use super::{
    ContigLexSortCheckPIOP, ContigLexSortCheckProverInput, ContigLexSortCheckVerifierInput,
};

#[test]
fn one_col_none_actv_contig_lex_sort_is_complete() -> SnarkResult<()> {
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![true],
        vec![false],
    )?;

    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![true],
        vec![true],
    )?;

    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([4, 3, 2, 1], Fr)],
        None,
        vec![to_field_vec!([3, 2, 1, 4], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![false],
        vec![false],
    )?;

    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([4, 3, 2, 1], Fr)],
        None,
        vec![to_field_vec!([3, 2, 1, 4], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![false],
        vec![true],
    )?;
    Ok(())
}

#[test]
fn one_col_with_actv_contig_lex_sort_is_complete() -> SnarkResult<()> {
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 5, 5, 7, 8, 1], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true],
        vec![false],
    )?;
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 2, 3, 4, 5, 5, 5, 8], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 5, 5, 5, 8, 1], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true],
        vec![true],
    )?;

    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([8, 7, 6, 6, 4, 3, 2, 1], Fr)],
        None,
        vec![to_field_vec!([7, 6, 6, 4, 3, 2, 1, 8], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![false],
        vec![false],
    )?;

    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([8, 7, 6, 5, 4, 4, 2, 1], Fr)],
        None,
        vec![to_field_vec!([7, 6, 5, 4, 4, 2, 1, 8], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![false],
        vec![true],
    )?;
    Ok(())
}

#[test]
fn multi_col_none_actv_contig_lex_sort_is_complete() -> SnarkResult<()> {
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 140, 99, 30], Fr),
        ],
        Some(vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([2, 3, 4, 5, 5, 7, 8, 1], Fr),
            to_field_vec!([70, 32, 12, 140, 140, 99, 30, 97], Fr),
        ],
        None,
        None,
        DataType::UInt32,
        vec![true, true],
        vec![false, false],
    )?;
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 250, 99, 30], Fr),
        ],
        Some(vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([2, 3, 4, 5, 5, 7, 8, 1], Fr),
            to_field_vec!([70, 32, 12, 140, 250, 99, 30, 97], Fr),
        ],
        None,
        None,
        DataType::UInt32,
        vec![true, true],
        vec![true, true],
    )?;
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 93, 93, 36, 175, 174, 27], Fr),
        ],
        Some(vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)]),
        vec![
            to_field_vec!([7, 7, 5, 4, 2, 2, 1, 8], Fr),
            to_field_vec!([93, 93, 93, 36, 175, 174, 27, 100], Fr),
        ],
        None,
        None,
        DataType::UInt32,
        vec![false, false],
        vec![false, false],
    )?;
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 90, 93, 36, 175, 174, 27], Fr),
        ],
        Some(vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)]),
        vec![
            to_field_vec!([7, 7, 5, 4, 2, 2, 1, 8], Fr),
            to_field_vec!([93, 90, 93, 36, 175, 174, 27, 100], Fr),
        ],
        None,
        None,
        DataType::UInt32,
        vec![false, false],
        vec![true, true],
    )?;
    Ok(())
}

#[test]
fn multi_col_with_actv_contig_lex_sort_is_complete() -> SnarkResult<()> {
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 140, 99, 30], Fr),
        ],
        Some(vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([2, 3, 4, 5, 5, 7, 8, 1], Fr),
            to_field_vec!([70, 32, 12, 140, 140, 99, 30, 97], Fr),
        ],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true, true],
        vec![false, false],
    )?;
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 5, 5], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 140, 140, 140], Fr),
        ],
        Some(vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([2, 3, 4, 5, 5, 5, 5, 1], Fr),
            to_field_vec!([70, 32, 12, 140, 140, 140, 140, 97], Fr),
        ],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true, true],
        vec![true, true],
    )?;
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 93, 93, 36, 175, 174, 27], Fr),
        ],
        Some(vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)]),
        vec![
            to_field_vec!([7, 7, 5, 4, 2, 2, 1, 8], Fr),
            to_field_vec!([93, 93, 93, 36, 175, 174, 27, 100], Fr),
        ],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![false, false],
        vec![false, false],
    )?;
    multi_col_sort_check_test_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 2], Fr),
            to_field_vec!([100, 93, 90, 93, 36, 175, 175, 175], Fr),
        ],
        Some(vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)]),
        vec![
            to_field_vec!([7, 7, 5, 4, 2, 2, 2, 8], Fr),
            to_field_vec!([93, 90, 93, 36, 175, 175, 175, 100], Fr),
        ],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![false, false],
        vec![true, true],
    )?;
    Ok(())
}

#[test]
fn one_col_none_actv_contig_lex_sort_is_sound() -> SnarkResult<()> {
    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![false],
        vec![false],
    )?;

    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![false],
        vec![true],
    )?;

    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([4, 3, 2, 1], Fr)],
        None,
        vec![to_field_vec!([3, 2, 1, 4], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![true],
        vec![false],
    )?;

    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([4, 3, 2, 1], Fr)],
        None,
        vec![to_field_vec!([3, 2, 1, 4], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![true],
        vec![true],
    )?;
    Ok(())
}

#[test]
fn one_col_with_actv_contig_lex_sort_is_sound() -> SnarkResult<()> {
    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 2, 3, 1, 5, 5, 7, 8], Fr)],
        None,
        vec![to_field_vec!([2, 3, 1, 5, 5, 7, 8, 1], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true],
        vec![false],
    )?;
    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([1, 2, 3, 4, 5, 5, 5, 8], Fr)],
        None,
        vec![to_field_vec!([2, 3, 4, 5, 5, 5, 8, 1], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true],
        vec![true],
    )?;

    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([8, 7, 6, 9, 4, 3, 2, 1], Fr)],
        None,
        vec![to_field_vec!([7, 6, 9, 4, 3, 2, 1, 8], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![false],
        vec![false],
    )?;

    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![to_field_vec!([8, 7, 6, 5, 4, 4, 2, 1], Fr)],
        None,
        vec![to_field_vec!([7, 6, 5, 4, 4, 2, 1, 8], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![false],
        vec![true],
    )?;
    Ok(())
}

#[test]
fn multi_col_none_actv_contig_lex_sort_is_sound() -> SnarkResult<()> {
    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 120, 99, 30], Fr),
        ],
        Some(vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([2, 3, 4, 5, 5, 7, 8, 1], Fr),
            to_field_vec!([70, 32, 12, 140, 120, 99, 30, 97], Fr),
        ],
        None,
        None,
        DataType::UInt32,
        vec![true, true],
        vec![false, false],
    )?;
    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 140, 99, 30], Fr),
        ],
        Some(vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)]),
        vec![
            to_field_vec!([2, 3, 4, 5, 5, 7, 8, 1], Fr),
            to_field_vec!([70, 32, 12, 140, 140, 99, 30, 97], Fr),
        ],
        None,
        None,
        DataType::UInt32,
        vec![true, true],
        vec![true, true],
    )?;
    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 94, 93, 36, 175, 176, 27], Fr),
        ],
        Some(vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)]),
        vec![
            to_field_vec!([7, 7, 5, 4, 2, 2, 1, 8], Fr),
            to_field_vec!([93, 94, 93, 36, 175, 176, 27, 100], Fr),
        ],
        None,
        None,
        DataType::UInt32,
        vec![false, false],
        vec![false, false],
    )?;
    multi_col_sort_check_soundness_helper::<DefaultSnarkBackend>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 93, 93, 36, 175, 176, 27], Fr),
        ],
        Some(vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)]),
        vec![
            to_field_vec!([7, 7, 5, 4, 2, 2, 1, 8], Fr),
            to_field_vec!([93, 93, 93, 36, 175, 176, 27, 100], Fr),
        ],
        None,
        None,
        DataType::UInt32,
        vec![false, false],
        vec![true, true],
    )?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn multi_col_sort_check_test_helper<B: SnarkBackend>(
    tracked_cols_values: Vec<Vec<B::F>>,
    tie_indicator_values: Option<Vec<Vec<B::F>>>,
    shift_values: Vec<Vec<B::F>>,
    shared_activator: Option<Vec<B::F>>,
    shift_activator: Option<Vec<B::F>>,
    data_type: DataType,
    ascending: Vec<bool>,
    strict: Vec<bool>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<B>()?;
    let activator_slice = shared_activator.as_deref();
    let shift_activator_slice = shift_activator.as_deref();

    let tracked_table = build_tracked_table(
        &mut prover,
        &tracked_cols_values,
        activator_slice,
        &data_type,
        "tracked",
    )?;
    let shift_tracked_table = build_tracked_table(
        &mut prover,
        &shift_values,
        shift_activator_slice,
        &data_type,
        "shift",
    )?;
    let row_len = tracked_cols_values
        .first()
        .map(|col| col.len())
        .expect("tracked columns must contain data");

    let tie_indicator_tracked_table = match tie_indicator_values {
        Some(values) => {
            if values.is_empty() {
                panic!("tie indicator columns cannot be empty when provided");
            }
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
                activator_slice,
                &DataType::Boolean,
                "tie_indicator",
            )?)
        }
        None => None,
    };

    let num_cols = tracked_table.num_data_tracked_cols();
    let tracked_table_for_verifier = tracked_table.clone();
    let shift_table_for_verifier = shift_tracked_table.clone();
    let tie_indicator_table_for_verifier = tie_indicator_tracked_table.clone();
    let ascending_flags = ascending;
    let strict_flags = strict;

    assert_eq!(
        ascending_flags.len(),
        num_cols,
        "ascending flags length must match number of tracked columns"
    );
    assert_eq!(
        strict_flags.len(),
        num_cols,
        "strict flags length must match number of tracked columns"
    );

    let prover_input = ContigLexSortCheckProverInput {
        tracked_table,
        tie_indicator_tracked_table,
        shift_tracked_table,
        ascending: ascending_flags.clone(),
        strict: strict_flags.clone(),
    };

    ContigLexSortCheckPIOP::<B>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let mut oracle_cache: HashMap<TrackerID, TrackedOracle<B>> = HashMap::new();

    let tracked_table_oracle =
        table_to_oracle(&mut verifier, tracked_table_for_verifier, &mut oracle_cache)?;
    let shift_tracked_table_oracle =
        table_to_oracle(&mut verifier, shift_table_for_verifier, &mut oracle_cache)?;
    let tie_indicator_tracked_table_oracle = tie_indicator_table_for_verifier
        .map(|table| table_to_oracle(&mut verifier, table, &mut oracle_cache))
        .transpose()?;

    let verifier_input = ContigLexSortCheckVerifierInput {
        tracked_table_oracle,
        tie_indicator_tracked_table_oracle,
        shift_tracked_table_oracle,
        ascending: ascending_flags,
        strict: strict_flags,
    };

    ContigLexSortCheckPIOP::<B>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn multi_col_sort_check_soundness_helper<B: SnarkBackend>(
    tracked_cols_values: Vec<Vec<B::F>>,
    tie_indicator_values: Option<Vec<Vec<B::F>>>,
    shift_values: Vec<Vec<B::F>>,
    shared_activator: Option<Vec<B::F>>,
    shift_activator: Option<Vec<B::F>>,
    data_type: DataType,
    ascending: Vec<bool>,
    strict: Vec<bool>,
) -> SnarkResult<()> {
    let result = multi_col_sort_check_test_helper::<B>(
        tracked_cols_values,
        tie_indicator_values,
        shift_values,
        shared_activator,
        shift_activator,
        data_type,
        ascending,
        strict,
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
            Ok(_) => {
                panic!("expected contig multi-column sort check to fail under honest-prover mode")
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        use ark_piop::{errors::SnarkError, verifier::errors::VerifierError};

        match result {
            Err(SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))) => Ok(()),
            Ok(_) => panic!("expected contig multi-column sort check to fail"),
            Err(err) => Err(err),
        }
    }
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

fn table_to_oracle<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    table: TrackedTable<B>,
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
