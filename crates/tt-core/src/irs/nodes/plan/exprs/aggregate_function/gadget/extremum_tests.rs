//! Proof-level regression tests for extremum broadcast and attainment checks.
//!
//! These tests run the real MAX/MIN gadget and all its descendants, including
//! Sign and both Lookup PIOPs. They fix group keys and Boolean activators as
//! committed inputs; Support/NoDup and SQL planning are tested separately.
//! Negative cases use only valid pointwise bounds, isolating the new lookups.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{INPUT_RLC_LABEL, OUTPUT_LABEL, OUTPUT_RLC_LABEL, input_label, max, min};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{
    GadgetHarness, TableSpec, run_gadget_pipeline_to_verifier,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn table(values: &[u64], activator: Option<&[u64]>) -> TableSpec<F> {
    let field = Arc::new(Field::new("value", DataType::UInt8, false));
    TableSpec {
        schema: Schema::new(vec![field.clone()]),
        log_size: values.len().ilog2() as usize,
        cols: vec![(field, values.iter().copied().map(F::from).collect())],
        activator: activator.map(|values| values.iter().copied().map(F::from).collect()),
    }
}

/// A successful return means proof construction completed; only its value is
/// the verifier result. No panic or prover error is accepted as rejection.
fn verify_extremum(
    maximum: bool,
    raw: &[u64],
    claims: &[u64],
    groups: &[u64],
    input_active: &[u64],
    output_active: &[u64],
) -> Result<(), SnarkError> {
    let gadget = Arc::new(Node::<B>::Gadget(if maximum {
        Arc::new(max::GadgetNode::<B>::new())
    } else {
        Arc::new(min::GadgetNode::<B>::new())
    }));
    let id = gadget.id();
    let input = input_label(0);
    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(id, &input, table(raw, Some(input_active)))
        .with_table(id, OUTPUT_LABEL, table(claims, Some(output_active)))
        .with_table(id, INPUT_RLC_LABEL, table(groups, None))
        .with_table(id, OUTPUT_RLC_LABEL, table(groups, None))
        .with_shared_activator(id, INPUT_RLC_LABEL, id, &input)
        .with_shared_activator(id, OUTPUT_RLC_LABEL, id, OUTPUT_LABEL)
        .build();
    run_gadget_pipeline_to_verifier(harness)
        .expect("extremum proof generation must succeed before checking verifier rejection")
}

#[test]
fn extremum_verifier_accepts_honest_max_and_min_in_two_groups() {
    for (maximum, claims) in [(true, [2, 2, 9, 9]), (false, [1, 1, 8, 8])] {
        verify_extremum(
            maximum,
            &[1, 2, 9, 8],
            &claims,
            &[7, 7, 8, 8],
            &[1, 1, 1, 1],
            &[1, 0, 1, 0],
        )
        .expect("honest extrema must verify, including attainment at another physical slot");
    }
}

#[test]
fn extremum_verifier_ignores_inactive_input_payloads() {
    for (maximum, raw, claims) in [
        (true, [1, 2, 250, 240], [2, 2, 0, 0]),
        (false, [1, 2, 0, 0], [1, 1, 250, 250]),
    ] {
        verify_extremum(
            maximum,
            &raw,
            &claims,
            &[7, 7, 99, 99],
            &[1, 1, 0, 0],
            &[1, 0, 0, 0],
        )
        .expect("inactive padding must not participate in extrema");
    }
}

// Honest-prover mode deliberately rejects false constraints before proof
// construction. Run these tests without that feature to test the verifier.
#[cfg(not(feature = "honest-prover"))]
mod rejection {
    use super::*;

    #[test]
    fn extremum_verifier_rejects_nonuniform_broadcast_claims() {
        for (maximum, claims) in [(true, [2, 3, 0, 0]), (false, [1, 0, 0, 0])] {
            assert!(
                verify_extremum(
                    maximum,
                    &[1, 2, 0, 0],
                    &claims,
                    &[7, 7, 0, 0],
                    &[1, 1, 0, 0],
                    &[1, 0, 0, 0],
                )
                .is_err(),
                "a correct active output claim must not license another broadcast value"
            );
        }
    }

    #[test]
    fn extremum_verifier_rejects_unattained_bounds() {
        for (maximum, claims) in [(true, [3, 3, 0, 0]), (false, [0, 0, 0, 0])] {
            assert!(
                verify_extremum(
                    maximum,
                    &[1, 2, 0, 0],
                    &claims,
                    &[7, 7, 0, 0],
                    &[1, 1, 0, 0],
                    &[1, 0, 0, 0],
                )
                .is_err(),
                "a uniform bound is not enough: an active input must attain it"
            );
        }
    }

    #[test]
    fn extremum_verifier_rejects_inactive_only_attainment() {
        for (maximum, raw, claims) in [
            (true, [1, 2, 3, 0], [3, 3, 3, 0]),
            (false, [1, 2, 0, 0], [0, 0, 0, 0]),
        ] {
            assert!(
                verify_extremum(
                    maximum,
                    &raw,
                    &claims,
                    &[7, 7, 7, 0],
                    &[1, 1, 0, 0],
                    &[0, 0, 1, 0],
                )
                .is_err(),
                "a matching raw row in inactive padding must not witness attainment"
            );
        }
    }
}
