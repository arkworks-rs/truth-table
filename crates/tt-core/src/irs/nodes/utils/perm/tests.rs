//! Tests for the `Permutation` gadget's column-folding rule.
//!
//! The gadget fingerprints selected row tuples with shared transcript
//! challenges before the keyed sumcheck. These tests cover column alignment,
//! honest permutations, and adversarial collisions against the former fixed
//! coefficients.

use std::sync::Arc;

use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, errors::SnarkError, verifier::errors::VerifierError,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{GadgetNode, LEFT_LABEL, RIGHT_LABEL, should_fold_by_names};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const NV: usize = 2; // n = 4

fn u64_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}

fn vals(xs: [u64; 4]) -> Vec<F> {
    xs.iter().map(|x| F::from(*x)).collect()
}

/// Run the gadget over two tables given as `(column name, evaluations)`
/// lists, in the flat order each side stores them.
fn run(
    left: &[(&str, [u64; 4])],
    right: &[(&str, [u64; 4])],
) -> Result<(), ark_piop::errors::SnarkError> {
    run_with_activators(left, right, None, None)
}

fn run_with_activators(
    left: &[(&str, [u64; 4])],
    right: &[(&str, [u64; 4])],
    left_activator: Option<[u64; 4]>,
    right_activator: Option<[u64; 4]>,
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget: Arc<Node<B>> = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new())));
    let gadget_id = gadget.id();

    let spec = |cols: &[(&str, [u64; 4])], activator: Option<[u64; 4]>| {
        let fields: Vec<_> = cols.iter().map(|(n, _)| u64_field(n)).collect();
        TableSpec {
            schema: Schema::new(
                fields
                    .iter()
                    .map(|f| f.as_ref().clone())
                    .collect::<Vec<_>>(),
            ),
            log_size: NV,
            cols: fields
                .iter()
                .zip(cols)
                .map(|(f, (_, v))| (f.clone(), vals(*v)))
                .collect(),
            activator: activator.map(vals),
        }
    };

    let harness = GadgetHarness::<B>::builder(6)
        .with_gadget(gadget)
        .with_table(gadget_id, LEFT_LABEL, spec(left, left_activator))
        .with_table(gadget_id, RIGHT_LABEL, spec(right, right_activator))
        .build();
    run_gadget_pipeline(harness)
}

// ---- the fold-selection rule ----

#[test]
fn same_names_in_a_different_order_fold_by_name() {
    // The TPC-H group-by shape: both sides carry the same columns, but
    // the output lists its key columns first and the input lists them
    // after the aggregates.
    assert!(should_fold_by_names(2, 2, &["b".into(), "a".into()]));
}

#[test]
fn divergent_counts_fold_by_name() {
    // One side dropped an arithmetization segment the other kept.
    assert!(should_fold_by_names(3, 2, &["a".into(), "b".into()]));
}

#[test]
fn equal_counts_with_uncorrelated_names_fold_positionally() {
    // The LIKE path: same column count, different labels, positional
    // meaning. An empty or partial name intersection must not be used.
    assert!(!should_fold_by_names(2, 2, &[]));
    assert!(!should_fold_by_names(2, 2, &["a".into()]));
}

#[test]
fn duplicate_names_fold_positionally() {
    // `fold_table_by_names` resolves a name to its first flat match, so
    // a duplicated name would fold one column twice.
    assert!(!should_fold_by_names(2, 2, &["a".into(), "a".into()]));
}

// ---- end-to-end ----

#[test]
fn reordered_columns_still_verify() {
    // RIGHT holds the same rows as LEFT — rotated by one — but stores
    // its columns in the opposite flat order. Folding positionally
    // would pair challenge 1 with `a` on the left and `b` on the right.
    let left = [("a", [10, 20, 30, 40]), ("b", [1, 2, 3, 4])];
    let right = [("b", [4, 1, 2, 3]), ("a", [40, 10, 20, 30])];
    run(&left, &right).expect("a permuted table with reordered columns must verify");
}

#[test]
fn reordered_columns_do_not_hide_a_non_permutation() {
    // Same reordering, but one `a` value is wrong. Name-based folding
    // must not turn this into an accepted proof.
    let left = [("a", [10, 20, 30, 40]), ("b", [1, 2, 3, 4])];
    let right = [("b", [4, 1, 2, 3]), ("a", [40, 10, 20, 99])];
    assert!(
        run(&left, &right).is_err(),
        "a non-permutation must be rejected regardless of column order"
    );
}

#[test]
fn matching_order_still_verifies() {
    let left = [("a", [10, 20, 30, 40]), ("b", [1, 2, 3, 4])];
    let right = [("a", [30, 40, 10, 20]), ("b", [3, 4, 1, 2])];
    run(&left, &right).expect("a permuted table with matching column order must verify");
}

#[test]
fn row_pairing_is_preserved() {
    // Each column is individually a permutation of the other side's,
    // but the (a, b) pairing is broken.
    let left = [("a", [10, 20, 30, 40]), ("b", [1, 2, 3, 4])];
    let right = [("a", [10, 20, 30, 40]), ("b", [2, 1, 3, 4])];
    assert!(
        run(&left, &right).is_err(),
        "shuffling one column independently must be rejected"
    );
}

#[test]
fn fixed_weight_collision_is_rejected_by_verifier() {
    // The old fingerprint a + 2*b maps both (0, 1) and (2, 0) to 2.
    // These committed tables therefore passed despite having different rows.
    let left = [("a", [0, 3, 5, 7]), ("b", [1, 2, 3, 4])];
    let right = [("a", [2, 3, 5, 7]), ("b", [0, 2, 3, 4])];
    assert!(matches!(
        run(&left, &right),
        Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(_)
        ))
    ));
}

#[test]
fn fixed_weight_collision_with_positional_aliases_is_rejected_by_verifier() {
    let left = [("a", [0, 3, 5, 7]), ("b", [1, 2, 3, 4])];
    let right = [("x", [2, 3, 5, 7]), ("y", [0, 2, 3, 4])];
    assert!(matches!(
        run(&left, &right),
        Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(_)
        ))
    ));
}

#[test]
fn positional_aliases_still_verify() {
    let left = [("a", [10, 20, 30, 40]), ("b", [1, 2, 3, 4])];
    let right = [("x", [40, 10, 20, 30]), ("y", [4, 1, 2, 3])];
    run(&left, &right).expect("positionally matching aliased columns must verify");
}

#[test]
fn partial_name_intersection_does_not_drop_a_column() {
    let left = [("a", [10, 20, 30, 40]), ("b", [1, 2, 3, 4])];
    let right = [("a", [40, 10, 20, 30]), ("alias_b", [4, 1, 2, 99])];
    assert!(matches!(
        run(&left, &right),
        Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(_)
        ))
    ));
}

#[test]
fn projected_name_fold_still_verifies() {
    // Rematerialization can compare a projected output against a wider input.
    // The common fingerprint must therefore use the selected-name width, not
    // either table's physical width.
    let left = [("a", [10, 20, 30, 40]), ("b", [1, 2, 3, 4])];
    let right = [("a", [40, 10, 20, 30])];
    run(&left, &right).expect("the selected shared projection must still verify");
}

#[test]
fn projected_multi_column_fold_uses_the_shared_width() {
    // The selected projection has width two although LEFT physically has
    // three columns. RIGHT also reverses the selected columns, exercising
    // both the shared-name order and its transcript-challenge count.
    let left = [
        ("a", [10, 20, 30, 40]),
        ("b", [1, 2, 3, 4]),
        ("unused", [100, 200, 300, 400]),
    ];
    let right = [("b", [4, 1, 2, 3]), ("a", [40, 10, 20, 30])];
    run(&left, &right).expect("the shared two-column projection must verify");
}

#[test]
fn single_column_permutations_remain_exact() {
    let left = [("a", [10, 20, 30, 40])];
    let right = [("a", [40, 10, 20, 30])];
    run(&left, &right).expect("a one-column permutation must verify");

    let tampered = [("a", [40, 10, 20, 99])];
    assert!(matches!(
        run(&left, &tampered),
        Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(_)
        ))
    ));
}

#[test]
fn inactive_payloads_are_ignored_but_active_rows_are_bound() {
    let left = [("a", [10, 20, 999, 998]), ("b", [1, 2, 99, 98])];
    let right = [("a", [20, 777, 10, 666]), ("b", [2, 77, 1, 66])];
    let left_activator = Some([1, 1, 0, 0]);
    let right_activator = Some([1, 0, 1, 0]);
    run_with_activators(&left, &right, left_activator, right_activator)
        .expect("equal active-row multisets must ignore inactive payloads");

    let tampered = [("a", [20, 777, 11, 666]), ("b", [2, 77, 1, 66])];
    assert!(matches!(
        run_with_activators(&left, &tampered, left_activator, right_activator),
        Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(_)
        ))
    ));
}
