use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
#[allow(unused_imports)]
use ark_piop::to_field_vec;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    prover::Prover,
    structs::TrackerID,
    test_utils::test_prelude,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::arrow::datatypes::{DataType, Field};
use std::{collections::HashMap, sync::Arc};

use super::{
    ContigLexSortCheckPIOP, ContigLexSortCheckProverInput, ContigLexSortCheckVerifierInput,
};

#[test]
fn one_col_none_actv_contig_lex_sort_is_complete() -> SnarkResult<()> {
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        vec![],
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![true],
        vec![false],
    )?;

    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        vec![],
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![true],
        vec![true],
    )?;

    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([4, 3, 2, 1], Fr)],
        vec![],
        vec![to_field_vec!([3, 2, 1, 4], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![false],
        vec![false],
    )?;

    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([4, 3, 2, 1], Fr)],
        vec![],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr)],
        vec![],
        vec![to_field_vec!([2, 3, 4, 5, 5, 7, 8, 1], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true],
        vec![false],
    )?;
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 4, 5, 5, 5, 8], Fr)],
        vec![],
        vec![to_field_vec!([2, 3, 4, 5, 5, 5, 8, 1], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true],
        vec![true],
    )?;

    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([8, 7, 6, 6, 4, 3, 2, 1], Fr)],
        vec![],
        vec![to_field_vec!([7, 6, 6, 4, 3, 2, 1, 8], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![false],
        vec![false],
    )?;

    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([8, 7, 6, 5, 4, 4, 2, 1], Fr)],
        vec![],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 140, 99, 30], Fr),
        ],
        vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 250, 99, 30], Fr),
        ],
        vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 93, 93, 36, 175, 174, 27], Fr),
        ],
        vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 90, 93, 36, 175, 174, 27], Fr),
        ],
        vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 140, 99, 30], Fr),
        ],
        vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 5, 5], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 140, 140, 140], Fr),
        ],
        vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 93, 93, 36, 175, 174, 27], Fr),
        ],
        vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)],
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
    multi_col_sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 2], Fr),
            to_field_vec!([100, 93, 90, 93, 36, 175, 175, 175], Fr),
        ],
        vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)],
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
    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        vec![],
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![false],
        vec![false],
    )?;

    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 4], Fr)],
        vec![],
        vec![to_field_vec!([2, 3, 4, 1], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![false],
        vec![true],
    )?;

    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([4, 3, 2, 1], Fr)],
        vec![],
        vec![to_field_vec!([3, 2, 1, 4], Fr)],
        None,
        None,
        DataType::UInt32,
        vec![true],
        vec![false],
    )?;

    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([4, 3, 2, 1], Fr)],
        vec![],
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
    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 1, 5, 5, 7, 8], Fr)],
        vec![],
        vec![to_field_vec!([2, 3, 1, 5, 5, 7, 8, 1], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true],
        vec![false],
    )?;
    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([1, 2, 3, 4, 5, 5, 5, 8], Fr)],
        vec![],
        vec![to_field_vec!([2, 3, 4, 5, 5, 5, 8, 1], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![true],
        vec![true],
    )?;

    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([8, 7, 6, 9, 4, 3, 2, 1], Fr)],
        vec![],
        vec![to_field_vec!([7, 6, 9, 4, 3, 2, 1, 8], Fr)],
        Some(to_field_vec!([1, 1, 1, 1, 1, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 1], Fr)),
        DataType::UInt32,
        vec![false],
        vec![false],
    )?;

    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![to_field_vec!([8, 7, 6, 5, 4, 4, 2, 1], Fr)],
        vec![],
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
    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 120, 99, 30], Fr),
        ],
        vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)],
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
    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([1, 2, 3, 4, 5, 5, 7, 8], Fr),
            to_field_vec!([97, 70, 32, 12, 140, 140, 99, 30], Fr),
        ],
        vec![to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr)],
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
    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 94, 93, 36, 175, 176, 27], Fr),
        ],
        vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)],
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
    multi_col_sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![
            to_field_vec!([8, 7, 7, 5, 4, 2, 2, 1], Fr),
            to_field_vec!([100, 93, 93, 93, 36, 175, 176, 27], Fr),
        ],
        vec![to_field_vec!([0, 1, 0, 0, 0, 1, 0, 0], Fr)],
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

pub(crate) fn multi_col_sort_check_test_helper<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    tracked_cols_values: Vec<Vec<F>>,
    tie_indicator_values: Vec<Vec<F>>,
    shift_values: Vec<Vec<F>>,
    shared_activator: Option<Vec<F>>,
    shift_activator: Option<Vec<F>>,
    data_type: DataType,
    ascending: Vec<bool>,
    strict: Vec<bool>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<F, MvPCS, UvPCS>()?;
    let activator_slice = shared_activator.as_deref();
    let shift_activator_slice = shift_activator.as_deref();

    let tracked_cols = build_tracked_cols(
        &mut prover,
        &tracked_cols_values,
        activator_slice,
        &data_type,
        "tracked",
    )?;
    let tie_indicator_cols = build_tracked_cols(
        &mut prover,
        &tie_indicator_values,
        activator_slice,
        &data_type,
        "tie",
    )?;
    let shift_cols = build_tracked_cols(
        &mut prover,
        &shift_values,
        shift_activator_slice,
        &data_type,
        "shift",
    )?;

    let num_cols = tracked_cols.len();
    let tracked_cols_for_verifier = tracked_cols.clone();
    let tie_cols_for_verifier = tie_indicator_cols.clone();
    let shift_cols_for_verifier = shift_cols.clone();
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
        tracked_cols,
        tie_indicator_tracked_cols: tie_indicator_cols,
        shift_tracked_cols: shift_cols,
        ascending: ascending_flags.clone(),
        strict: strict_flags.clone(),
    };

    ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let mut oracle_cache: HashMap<TrackerID, TrackedOracle<F, MvPCS, UvPCS>> = HashMap::new();

    let tracked_col_oracles =
        cols_to_oracles(&mut verifier, &tracked_cols_for_verifier, &mut oracle_cache)?;
    let tie_indicator_col_oracles =
        cols_to_oracles(&mut verifier, &tie_cols_for_verifier, &mut oracle_cache)?;
    let shift_col_oracles =
        cols_to_oracles(&mut verifier, &shift_cols_for_verifier, &mut oracle_cache)?;

    let verifier_input = ContigLexSortCheckVerifierInput {
        tracked_col_oracles,
        tie_indicator_tracked_col_oracles: tie_indicator_col_oracles,
        shift_tracked_col_oracles: shift_col_oracles,
        ascending: ascending_flags,
        strict: strict_flags,
    };

    ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;
    Ok(())
}

pub(crate) fn multi_col_sort_check_soundness_helper<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    tracked_cols_values: Vec<Vec<F>>,
    tie_indicator_values: Vec<Vec<F>>,
    shift_values: Vec<Vec<F>>,
    shared_activator: Option<Vec<F>>,
    shift_activator: Option<Vec<F>>,
    data_type: DataType,
    ascending: Vec<bool>,
    strict: Vec<bool>,
) -> SnarkResult<()> {
    let result = multi_col_sort_check_test_helper::<F, MvPCS, UvPCS>(
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
            },
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

fn build_tracked_cols<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    prover: &mut Prover<F, MvPCS, UvPCS>,
    column_values: &[Vec<F>],
    shared_activator: Option<&[F]>,
    data_type: &DataType,
    prefix: &str,
) -> SnarkResult<Vec<TrackedCol<F, MvPCS, UvPCS>>> {
    if column_values.is_empty() {
        return Ok(Vec::new());
    }

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

    let shared_activator_poly = match shared_activator {
        Some(activator_values) => Some(
            prover
                .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, activator_values))?,
        ),
        None => None,
    };

    let mut cols = Vec::with_capacity(column_values.len());
    for (idx, values) in column_values.iter().enumerate() {
        assert_eq!(
            values.len(),
            len,
            "all columns must have identical number of rows"
        );
        let data_poly =
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, values))?;
        let field_ref = Some(Arc::new(Field::new(
            format!("{prefix}_col_{idx}"),
            data_type.clone(),
            false,
        )));
        cols.push(TrackedCol::new(
            data_poly,
            shared_activator_poly.clone(),
            field_ref,
        ));
    }
    Ok(cols)
}

fn cols_to_oracles<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    cols: &[TrackedCol<F, MvPCS, UvPCS>],
    cache: &mut HashMap<TrackerID, TrackedOracle<F, MvPCS, UvPCS>>,
) -> SnarkResult<Vec<TrackedColOracle<F, MvPCS, UvPCS>>> {
    cols.iter()
        .map(|col| tracked_col_to_oracle(verifier, col, cache))
        .collect()
}

fn tracked_col_to_oracle<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    col: &TrackedCol<F, MvPCS, UvPCS>,
    cache: &mut HashMap<TrackerID, TrackedOracle<F, MvPCS, UvPCS>>,
) -> SnarkResult<TrackedColOracle<F, MvPCS, UvPCS>> {
    let activator_oracle = match col.activator_tracked_poly() {
        Some(activator) => Some(track_oracle_cached(verifier, activator.id(), cache)?),
        None => None,
    };
    let data_oracle = track_oracle_cached(verifier, col.data_tracked_poly().id(), cache)?;

    Ok(TrackedColOracle::new(
        data_oracle,
        activator_oracle,
        col.field_ref(),
    ))
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
