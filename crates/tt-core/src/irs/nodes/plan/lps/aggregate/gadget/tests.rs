//! Tests of the aggregate wrapper's ungrouped extremum cardinality check.
//!
//! The expression-level MAX/MIN gadget is tested separately. Here the actual
//! Aggregate gadget and its Booleanity child must enforce exactly one output
//! representative, independent of lookup or comparison preconditions.

use super::*;
use ark_piop::{DefaultSnarkBackend, errors::SnarkError};
use datafusion::{arrow::datatypes::Schema, logical_expr::LogicalPlanBuilder, prelude::lit};
use datafusion_functions_aggregate::expr_fn::{max, min};

use crate::test_utils::gadget_harness::{
    GadgetHarness, TableSpec, run_gadget_pipeline_to_verifier,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn verify_ungrouped_extremum(maximum: bool, activator: Vec<F>) -> Result<(), SnarkError> {
    let input = LogicalPlanBuilder::empty(false)
        .build()
        .expect("empty logical input plan");
    let expression = if maximum {
        max(lit(1i64))
    } else {
        min(lit(1i64))
    }
    .alias("extremum");
    let aggregate = Aggregate::try_new(Arc::new(input), vec![], vec![expression])
        .expect("ungrouped extremum aggregate");
    let gadget = Arc::new(Node::<B>::Gadget(Arc::new(GadgetNode::new(aggregate))));
    let id = gadget.id();
    let field = Arc::new(Field::new("extremum", DataType::UInt8, false));
    let output = TableSpec {
        schema: Schema::new(vec![field.clone()]),
        log_size: 2,
        cols: vec![(field, vec![F::from(1u64); 4])],
        activator: Some(activator),
    };
    let harness = GadgetHarness::<B>::builder(2)
        // The production tracking path accepts explicit commitments to zero
        // columns too. Avoid the backend's unrelated constant-only proof bug;
        // the verifier still receives and checks the actual all-zero activator.
        .with_explicit_commitments()
        .with_gadget(gadget)
        .with_table(id, OUTPUT_LABEL, output)
        .build();
    run_gadget_pipeline_to_verifier(harness)
        .expect("aggregate proof generation must succeed before checking verifier rejection")
}

#[test]
fn extremum_ungrouped_verifier_accepts_one_active_representative() {
    for maximum in [true, false] {
        verify_ungrouped_extremum(maximum, [0, 0, 1, 0].into_iter().map(F::from).collect())
            .expect("one Boolean active representative must verify");
    }
}

// Prechecks under honest-prover intentionally stop before the verifier.
#[cfg(not(feature = "honest-prover"))]
mod rejection {
    use super::*;

    #[test]
    fn extremum_ungrouped_verifier_rejects_missing_representative() {
        for maximum in [true, false] {
            assert!(
                verify_ungrouped_extremum(maximum, vec![F::from(0u64); 4]).is_err(),
                "Booleanity alone must not allow zero representatives"
            );
        }
    }

    #[test]
    fn extremum_ungrouped_verifier_rejects_duplicate_representatives() {
        for maximum in [true, false] {
            assert!(
                verify_ungrouped_extremum(
                    maximum,
                    [1, 1, 0, 0].into_iter().map(F::from).collect(),
                )
                .is_err(),
                "Booleanity alone must not allow two representatives"
            );
        }
    }

    #[test]
    fn extremum_ungrouped_verifier_rejects_nonboolean_activator_with_sum_one() {
        for maximum in [true, false] {
            assert!(
                verify_ungrouped_extremum(
                    maximum,
                    vec![F::from(2u64), -F::from(1u64), F::from(0u64), F::from(0u64)],
                )
                .is_err(),
                "sum one alone must not allow non-Boolean cancellation"
            );
        }
    }
}
