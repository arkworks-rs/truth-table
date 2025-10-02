use super::*;

use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::{kzg10::KZG10, pst13::PST13, PCS},
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use arithmetic::{
    col::ArithCol,
    col_oracle::ArithColOracle,
    table::ArithTable,
    table_oracle::ArithTableOracle,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef},
    logical_expr::{Expr, Filter, LogicalPlanBuilder},
    scalar::ScalarValue,
};

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
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
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
            SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim
                )
            )
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
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    predicate_values: Vec<Fr>,
    input_activator_values: Option<Vec<Fr>>,
    output_activator_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    let predicate_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &predicate_values))?;
    let predicate_col = ArithCol::new(
        Some(DataType::Boolean),
        predicate_poly.clone(),
        None,
    );

    let table_len = predicate_values.len();
    let data_values = predicate_values.clone();

    let input_data_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &data_values))?;
    let input_data_field: FieldRef = Arc::new(Field::new("col0", DataType::UInt64, false));

    let mut input_columns = vec![(input_data_field.clone(), input_data_poly.clone())];
    if let Some(values) = input_activator_values {
        let activator_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &values))?;
        input_columns.push((
            Arc::new(Field::new("activator", DataType::Boolean, false)),
            activator_poly,
        ));
    }
    let input_table = ArithTable::new(None, input_columns, table_len);

    let output_data_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &data_values))?;
    let output_data_field: FieldRef = Arc::new(Field::new("col0", DataType::UInt64, false));

    let mut output_columns = vec![(output_data_field.clone(), output_data_poly.clone())];
    if let Some(values) = output_activator_values {
        let activator_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &values))?;
        output_columns.push((
            Arc::new(Field::new("activator", DataType::Boolean, false)),
            activator_poly,
        ));
    }
    let output_table = ArithTable::new(None, output_columns, table_len);

    let filter = dummy_filter();
    let prover_input = FilterPIOPProverInput {
        filter: filter.clone(),
        predicate_col: predicate_col.clone(),
        input_arith_table: input_table.clone(),
        output_table: output_table.clone(),
    };

    FilterPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let predicate_data_oracle = verifier.track_mv_com_by_id(predicate_poly.id())?;
    let predicate_oracle = ArithColOracle::new(
        predicate_col.data_type(),
        predicate_data_oracle,
        None,
        nv,
    );

    let input_arith_table_oracle = ArithTableOracle::from(input_table, &mut verifier)?;
    let output_arith_table_oracle = ArithTableOracle::from(output_table, &mut verifier)?;

    let verifier_input = FilterPIOPVerifierInput {
        filter,
        predicate_oracle,
        input_arith_table_oracle,
        output_arith_table_oracle,
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
