use super::*;

use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
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
    arrow::datatypes::{DataType, Field, FieldRef, Schema},
    common::{Column, DFSchema},
    logical_expr::{Aggregate, EmptyRelation, Expr, LogicalPlan},
};
use indexmap::IndexMap;

// #[test]
// fn aggregate_check_is_complete_for_grouped_column() -> SnarkResult<()> {
//     aggregate_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
//         2,
//         to_field_vec!([1, 1, 2, 2], Fr),
//         None,
//         to_field_vec!([1, 2, 0, 0], Fr),
//         Some(to_field_vec!([1, 1, 0, 0], Fr)),
//     )
// }

// #[test]
// fn aggregate_check_is_sound_when_output_contains_unknown_group() ->
// SnarkResult<()> {     aggregate_check_test_soundness_helper::<Fr,
// PST13<Bls12_381>, KZG10<Bls12_381>>(         2,
//         to_field_vec!([1, 1, 2, 2], Fr),
//         None,
//         to_field_vec!([1, 3, 0, 0], Fr),
//         Some(to_field_vec!([1, 1, 0, 0], Fr)),
//     )
// }

fn aggregate_check_test_soundness_helper<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    nv: usize,
    input_group_values: Vec<F>,
    input_activator_values: Option<Vec<F>>,
    output_group_values: Vec<F>,
    output_activator_values: Option<Vec<F>>,
) -> SnarkResult<()> {
    let err = aggregate_check_test_helper::<F, MvPCS, UvPCS>(
        nv,
        input_group_values,
        input_activator_values,
        output_group_values,
        output_activator_values,
    )
    .unwrap_err();

    #[cfg(feature = "honest-prover")]
    {
        use ark_piop::prover::errors::{HonestProverError, ProverError};
        assert!(matches!(
            err,
            SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim
            ))
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        use ark_piop::verifier::errors::VerifierError;
        assert!(matches!(
            err,
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))
        ));
    }

    Ok(())
}

fn aggregate_check_test_helper<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    nv: usize,
    input_group_values: Vec<F>,
    input_activator_values: Option<Vec<F>>,
    output_group_values: Vec<F>,
    output_activator_values: Option<Vec<F>>,
) -> SnarkResult<()> {
    let expected_len = 1usize << nv;
    assert_eq!(
        input_group_values.len(),
        expected_len,
        "input group column must have 2^nv entries"
    );
    assert_eq!(
        output_group_values.len(),
        expected_len,
        "output group column must have 2^nv entries"
    );

    if let Some(ref activator) = input_activator_values {
        assert_eq!(
            activator.len(),
            expected_len,
            "input activator must have 2^nv entries"
        );
    }
    if let Some(ref activator) = output_activator_values {
        assert_eq!(
            activator.len(),
            expected_len,
            "output activator must have 2^nv entries"
        );
    }

    let (mut prover, mut verifier) = test_prelude::<F, MvPCS, UvPCS>()?;

    let group_field: FieldRef =
        Arc::new(Field::new("customer.c_nationkey", DataType::UInt64, false));

    let aggregate = dummy_aggregate();

    let input_group_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &input_group_values))?;
    let mut input_columns = IndexMap::from([(group_field.clone(), input_group_poly)]);
    if let Some(values) = input_activator_values {
        let activator_poly =
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &values))?;
        input_columns.insert(
            Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false)),
            activator_poly,
        );
    }
    let input_grouping_table = TrackedTable::new(None, input_columns, nv);

    let output_group_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &output_group_values))?;
    let mut output_columns = IndexMap::from([(group_field.clone(), output_group_poly)]);
    if let Some(values) = output_activator_values {
        let activator_poly =
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &values))?;
        output_columns.insert(
            Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false)),
            activator_poly,
        );
    }
    let output_grouping_table = TrackedTable::new(None, output_columns, nv);

    let prover_input = AggregatePIOPProverInput {
        aggregate: aggregate.clone(),
        input_grouping_table: input_grouping_table.clone(),
        output_grouping_table: output_grouping_table.clone(),
        grouping_multiplicity_tracked_poly: todo!(),
    };

    AggregatePIOP::<F, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let input_grouping_oracle =
        TrackedTableOracle::from_tracked_table(input_grouping_table, &mut verifier)?;
    let output_grouping_oracle =
        TrackedTableOracle::from_tracked_table(output_grouping_table, &mut verifier)?;

    let verifier_input = AggregatePIOPVerifierInput {
        aggregate,
        input_grouping_table_oracle: input_grouping_oracle,
        output_grouping_table_oracle: output_grouping_oracle,
        grouping_multiplicty_tracked_oracle: todo!(),
    };

    AggregatePIOP::<F, MvPCS, UvPCS>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;

    Ok(())
}

fn dummy_aggregate() -> Aggregate {
    let arrow_schema = Arc::new(Schema::new(vec![Field::new(
        "customer.c_nationkey",
        DataType::UInt64,
        false,
    )]));
    let df_schema = Arc::new(
        DFSchema::try_from(Arc::clone(&arrow_schema))
            .expect("DF schema construction should succeed"),
    );

    let input_plan = LogicalPlan::EmptyRelation(EmptyRelation {
        produce_one_row: false,
        schema: df_schema,
    });

    Aggregate::try_new(
        Arc::new(input_plan),
        vec![Expr::Column(Column::from_name("customer.c_nationkey"))],
        vec![],
    )
    .expect("aggregate logical plan should build")
}
