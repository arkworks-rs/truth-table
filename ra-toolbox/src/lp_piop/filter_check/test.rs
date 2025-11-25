use super::*;

use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef},
    logical_expr::{Expr, Filter, LogicalPlanBuilder},
    scalar::ScalarValue,
};
use indexmap::IndexMap;

#[test]
fn filter_check_is_complete_with_both_activators_none() -> SnarkResult<()> {
    filter_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        None,
        None,
    )
}

#[test]
fn filter_check_is_sound_with_both_activators_none() -> SnarkResult<()> {
    filter_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 1, 1, 1, 1, 1, 1], Fr),
        None,
        None,
    )
}

#[test]
fn filter_check_is_complete_with_input_activator_only() -> SnarkResult<()> {
    filter_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr)),
        None,
    )
}

#[test]
fn filter_check_is_sound_with_input_activator_only() -> SnarkResult<()> {
    filter_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 1, 1, 1, 1, 1, 1], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr)),
        None,
    )
}

#[test]
fn filter_check_is_complete_with_output_activator_only() -> SnarkResult<()> {
    filter_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 1, 0, 1, 0, 1, 0], Fr),
        None,
        Some(to_field_vec!([1, 0, 1, 0, 1, 0, 1, 0], Fr)),
    )
}

#[test]
fn filter_check_is_sound_with_output_activator_only() -> SnarkResult<()> {
    filter_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 1, 0, 1, 0, 1, 0], Fr),
        None,
        Some(to_field_vec!([1, 1, 1, 0, 1, 0, 1, 0], Fr)),
    )
}

#[test]
fn filter_check_is_complete_with_both_activators_set() -> SnarkResult<()> {
    filter_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 1, 1, 1, 1, 0, 0], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 0, 1, 1, 0, 0, 0, 0], Fr)),
    )
}

#[test]
fn filter_check_is_sound_with_both_activators_set() -> SnarkResult<()> {
    filter_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 1, 1, 1, 1, 0, 0], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 0, 0, 0, 0], Fr)),
        Some(to_field_vec!([1, 0, 0, 1, 0, 0, 0, 0], Fr)),
    )
}

fn filter_check_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>> + 'static + Send + Sync,
    UvPCS: PCS<Fr, Poly = LDE<Fr>> + 'static + Send + Sync,
>(
    nv: usize,
    predicate_values: Vec<Fr>,
    input_activator_values: Option<Vec<Fr>>,
    output_activator_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let err = filter_check_test_helper::<Fr, MvPCS, UvPCS>(
        nv,
        predicate_values,
        input_activator_values,
        output_activator_values,
    )
    .unwrap_err();

    #[cfg(feature = "honest-prover")]
    {
        assert!(matches!(
            err,
            SnarkError::ProverError(ark_piop::prover::errors::ProverError::HonestProverError(
                ark_piop::prover::errors::HonestProverError::FalseClaim
            ))
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        assert!(matches!(
            err,
            SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(_)
            )
        ));
    }

    Ok(())
}

fn filter_check_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>> + 'static + Send + Sync,
    UvPCS: PCS<Fr, Poly = LDE<Fr>> + 'static + Send + Sync,
>(
    nv: usize,
    predicate_values: Vec<Fr>,
    input_activator_values: Option<Vec<Fr>>,
    output_activator_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    let predicate_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &predicate_values))?;
    let predicate_field = Field::new("predicate", DataType::Boolean, false);
    let predicate_col = TrackedCol::new(
        predicate_poly.clone(),
        None,
        Some(Arc::new(predicate_field)),
    );

    let table_len = predicate_values.len();
    let table_log_size = (table_len as f64).log2() as usize;
    let data_values = predicate_values.clone();

    let input_data_tracked_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &data_values))?;
    let input_data_field: FieldRef = Arc::new(Field::new("col0", DataType::UInt64, false));

    let mut input_columns =
        IndexMap::from([(input_data_field.clone(), input_data_tracked_poly.clone())]);
    if let Some(values) = input_activator_values {
        let activator_tracked_poly =
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &values))?;
        input_columns.insert(
            Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false)),
            activator_tracked_poly,
        );
    }
    let input_table = TrackedTable::new(None, input_columns, table_log_size);

    let output_data_tracked_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &data_values))?;
    let output_data_field: FieldRef = Arc::new(Field::new("col0", DataType::UInt64, false));

    let mut output_columns =
        IndexMap::from([(output_data_field.clone(), output_data_tracked_poly.clone())]);
    if let Some(values) = output_activator_values {
        let activator_tracked_poly =
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &values))?;
        output_columns.insert(
            Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false)),
            activator_tracked_poly,
        );
    }
    let table_log_size = (table_len as f64).log2() as usize;
    let output_tracked_table = TrackedTable::new(None, output_columns, table_log_size);

    let filter = dummy_filter();
    let prover_input = FilterPIOPProverInput {
        filter: filter.clone(),
        predicate_col: predicate_col.clone(),
        input_tracked_table: input_table.clone(),
        output_tracked_table: output_tracked_table.clone(),
    };

    FilterPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let predicate_data_tracked_oracle = verifier.track_mv_com_by_id(predicate_poly.id())?;
    let predicate_oracle = TrackedColOracle::new(
        predicate_data_tracked_oracle,
        None,
        predicate_col.field_ref(),
    );

    let input_tracked_table_oracle =
        TrackedTableOracle::from_tracked_table(input_table, &mut verifier)?;
    let output_tracked_table_oracle =
        TrackedTableOracle::from_tracked_table(output_tracked_table, &mut verifier)?;

    let verifier_input = FilterPIOPVerifierInput {
        filter,
        predicate_oracle,
        input_tracked_table_oracle,
        output_tracked_table_oracle,
    };

    FilterPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;
    Ok(())
}

fn dummy_filter() -> Filter {
    let plan = LogicalPlanBuilder::empty(false)
        .build()
        .expect("empty plan should build");
    Filter::try_new(
        Expr::Literal(ScalarValue::Boolean(Some(true))),
        Arc::new(plan),
    )
    .expect("filter should build")
}
