//! Tests for Bézout's NoDupcheck on hand-built four-row inputs.

use std::sync::Arc;

use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    errors::SnarkError,
    prover::errors::{HonestProverError, ProverError},
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{GadgetNode, INPUT_LABEL, Mode, bezout::FORGE_PRODUCT};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{
    GadgetHarness, TableSpec, run_gadget_pipeline_to_verifier,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const NV: usize = 2;

fn run(cols: &[&[u64]], activator: Option<&[u64]>) -> Result<Result<(), SnarkError>, SnarkError> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        Mode::BezoutBased,
    ))));
    let id = gadget.id();
    let fields: Vec<Arc<Field>> = (0..cols.len())
        .map(|i| Arc::new(Field::new(format!("c{i}"), DataType::UInt64, false)))
        .collect();
    let field_vec = |values: &[u64]| values.iter().map(|&v| F::from(v)).collect::<Vec<_>>();
    let harness = GadgetHarness::<B>::builder(6)
        .with_gadget(gadget)
        .with_table(
            id,
            INPUT_LABEL,
            TableSpec {
                schema: Schema::new(
                    fields
                        .iter()
                        .map(|field| field.as_ref().clone())
                        .collect::<Vec<_>>(),
                ),
                log_size: NV,
                cols: fields
                    .iter()
                    .cloned()
                    .zip(cols.iter().map(|col| field_vec(col)))
                    .collect(),
                activator: activator.map(field_vec),
            },
        )
        .build();
    run_gadget_pipeline_to_verifier(harness)
}

#[test]
fn distinct_values_verify() {
    run(&[&[3, 1, 4, 2]], None).unwrap().unwrap();
}

#[test]
fn duplicates_on_inactive_rows_verify() {
    run(&[&[5, 5, 7, 5]], Some(&[1, 0, 1, 0])).unwrap().unwrap();
}

#[test]
fn no_active_row_verifies() {
    run(&[&[5, 5, 5, 5]], Some(&[0, 0, 0, 0])).unwrap().unwrap();
}

#[test]
fn one_active_row_verifies() {
    run(&[&[5, 5, 5, 5]], Some(&[0, 0, 1, 0])).unwrap().unwrap();
}

#[test]
fn distinct_rows_of_two_columns_verify() {
    run(&[&[1, 1, 2, 2], &[2, 3, 2, 3]], None).unwrap().unwrap();
}

#[test]
fn a_duplicate_active_value_is_rejected() {
    let verdict = run(&[&[5, 1, 7, 5]], Some(&[1, 1, 1, 1])).unwrap();
    assert!(
        matches!(&verdict, Err(SnarkError::VerifierError(e)) if e.to_string().contains("Bezout identity")),
        "{verdict:?}"
    );
}

/// With duplicates, the prover sets `P(1, …, 1)` to the value that passes
/// the Bézout identity: only the recurrence ties `P` to the leaves. With
/// `honest-prover` the prover refuses the false recurrence itself.
#[test]
fn a_forged_running_product_is_rejected() {
    FORGE_PRODUCT.set(true);
    let result = run(&[&[5, 1, 7, 5]], None);
    FORGE_PRODUCT.set(false);
    let rejected = if cfg!(feature = "honest-prover") {
        matches!(
            result,
            Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim
            )))
        )
    } else {
        matches!(&result, Ok(Err(SnarkError::VerifierError(e))) if !e.to_string().contains("Bezout identity"))
    };
    assert!(rejected, "{result:?}");
}
