//! The non-wrap comparison mask is public, not a prover-chosen tie witness.
//!
//! These tests isolate that requirement. They do not establish consistency of
//! the separate adjacent-difference witnesses with the sorted table.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::assert_soundness_error};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    DIFF_INPUT_LABEL, GadgetNode, ROTATED_INPUT_LABEL, SortConfig, TABLE_LABEL,
    TIE_INDICATOR_LABEL, UniformConfig, prepend_first_tie_indicator_prover,
};
use crate::{
    irs::{
        nodes::{IsNode, Node, utils::nodup},
        payloads::PayloadStructure,
    },
    test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline},
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn spec(name: &str, values: &[i64], active: bool) -> TableSpec<F> {
    assert!(values.len().is_power_of_two());
    // Small integer columns keep the Sign gadget's public range table small;
    // these cases exercise mask binding, not integer-width boundaries.
    let data_type = if name.starts_with("tie_") {
        DataType::Boolean
    } else {
        DataType::Int8
    };
    let field = Arc::new(Field::new(name, data_type, false));
    let mut fields = vec![field.clone()];
    if active {
        fields.push(arithmetic::ACTIVATOR_FIELD.clone());
    }
    TableSpec {
        schema: Schema::new(fields),
        log_size: values.len().ilog2() as usize,
        cols: vec![(field, values.iter().copied().map(F::from).collect())],
        activator: active.then(|| vec![F::from(1u64); values.len()]),
    }
}

fn harness(values: &[i64], claimed_first_tie: &[i64], asc: bool, strict: bool) -> GadgetHarness<B> {
    harness_with_optional_tie(values, Some(claimed_first_tie), asc, strict)
}

fn harness_with_optional_tie(
    values: &[i64],
    claimed_first_tie: Option<&[i64]>,
    asc: bool,
    strict: bool,
) -> GadgetHarness<B> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        SortConfig::Uniform(UniformConfig { asc, strict }),
    ))));
    let id = gadget.id();
    let mut rotated = values.to_vec();
    rotated.rotate_left(1);
    let diff: Vec<_> = rotated
        .iter()
        .zip(values)
        .map(|(next, cur)| if asc { next - cur } else { cur - next })
        .collect();
    let builder = GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(id, TABLE_LABEL, spec("key", values, true))
        .with_table(id, ROTATED_INPUT_LABEL, spec("key", &rotated, true))
        .with_table(id, DIFF_INPUT_LABEL, spec("key", &diff, false));
    match claimed_first_tie {
        Some(tie) => builder.with_table(id, TIE_INDICATOR_LABEL, spec("tie_0", tie, false)),
        None => builder,
    }
    .build()
}

fn nodup_harness(values: &[i64], claimed_first_tie: &[i64]) -> GadgetHarness<B> {
    let gadget = Arc::new(Node::Gadget(Arc::new(nodup::GadgetNode::<B>::default())));
    let id = gadget.id();
    let sort = gadget
        .children()
        .into_iter()
        .find(|child| child.name() == "Contiguous Sort")
        .expect("SortBased NoDup must contain its sort child");
    let mut rotated = values.to_vec();
    rotated.rotate_left(1);
    // NoDup uses a strict descending sort. Keep the difference witness
    // truthful so this regression cannot depend on the separate diff fix.
    let diff: Vec<_> = values
        .iter()
        .zip(&rotated)
        .map(|(cur, next)| cur - next)
        .collect();
    GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(id, nodup::INPUT_LABEL, spec("key", values, true))
        .with_table(id, nodup::LEX_SORTED_LABEL, spec("key", values, true))
        .with_table(sort.id(), ROTATED_INPUT_LABEL, spec("key", &rotated, true))
        .with_table(sort.id(), DIFF_INPUT_LABEL, spec("key", &diff, false))
        .with_table(
            sort.id(),
            TIE_INDICATOR_LABEL,
            spec("tie_0", claimed_first_tie, false),
        )
        .build()
}

fn assert_false_sort_rejected(harness: GadgetHarness<B>, message: &str) {
    // Without the diagnostic feature, require a completed proof and an actual
    // verifier rejection; a prover-side error is not a soundness regression.
    #[cfg(not(feature = "honest-prover"))]
    let error = crate::test_utils::gadget_harness::run_gadget_pipeline_to_verifier(harness)
        .expect("malformed sort witness must reach verification")
        .expect_err(message);
    // The diagnostic feature deliberately stops false claims in the prover.
    #[cfg(feature = "honest-prover")]
    let error = run_gadget_pipeline(harness).expect_err(message);
    assert_soundness_error(error);
}

#[test]
fn supplied_first_tie_is_replaced_by_the_public_mask() {
    let mut harness = harness(&[1, 2, 3, 4], &[0, 0, 0, 0], true, false);
    let table = match harness.prover_ir.payload_for_node(&harness.node_id) {
        Some(PayloadStructure::GadgetPayload(payload)) => &payload[TIE_INDICATOR_LABEL],
        _ => panic!("missing test payload"),
    };
    let fixed = prepend_first_tie_indicator_prover(&mut harness.prover, Some(table), 2);
    assert_eq!(fixed.data_tracked_polys_indices().len(), 1);
    let schema = fixed.schema_ref().expect("mask table should have a schema");
    assert_eq!(schema.fields().len(), 1);
    assert_eq!(schema.field(0).name(), "tie_0");
    assert_eq!(schema.field(0).data_type(), &DataType::Boolean);
    assert_eq!(
        fixed
            .tracked_col_by_ind(0)
            .data_tracked_poly()
            .evaluations(),
        vec![F::from(1u64), F::from(1u64), F::from(1u64), F::from(0u64)]
    );
}

#[test]
fn public_mask_accepts_sorted_rows_and_ignores_wraparound() {
    run_gadget_pipeline(harness(&[1, 2, 3, 4], &[0, 0, 0, 0], true, false)).unwrap();
}

#[test]
fn zero_first_tie_cannot_hide_a_descending_adjacent_pair() {
    assert_false_sort_rejected(
        harness(&[2, 1, 3, 4], &[0, 0, 0, 0], true, false),
        "a supplied zero mask must not disable adjacent comparisons",
    );
}

#[test]
fn singleton_has_no_adjacent_comparison() {
    run_gadget_pipeline(harness(&[7], &[1], true, true)).unwrap();
}

#[test]
fn strict_sort_rejects_duplicates_despite_zero_first_tie() {
    assert_false_sort_rejected(
        harness(&[1, 1, 2, 3], &[0, 0, 0, 0], true, true),
        "a strict sort must reject duplicate active keys",
    );
}

#[test]
fn nonstrict_sort_allows_duplicate_keys() {
    run_gadget_pipeline(harness(&[1, 1, 2, 3], &[0, 0, 0, 0], true, false)).unwrap();
}

#[test]
fn nodup_rejects_duplicate_groups_despite_zero_first_tie() {
    // Same keys, same activators, truthful rotation, truthful differences;
    // only the untrusted first-tie witness attempts to suppress the check.
    assert_false_sort_rejected(
        nodup_harness(&[3, 2, 1, 1], &[0, 0, 0, 0]),
        "NoDup must reject duplicate active grouping keys",
    );
}

#[test]
fn nodup_accepts_distinct_keys_with_public_mask() {
    run_gadget_pipeline(nodup_harness(&[4, 3, 2, 1], &[0, 0, 0, 0])).unwrap();
}

#[test]
fn single_key_sort_accepts_a_dropped_tie_hint() {
    run_gadget_pipeline(harness_with_optional_tie(&[1, 2, 3, 4], None, true, true)).unwrap();
}

#[test]
fn dropping_tie_hint_cannot_disable_duplicate_check() {
    assert_false_sort_rejected(
        harness_with_optional_tie(&[1, 1, 2, 3], None, true, true),
        "the public mask must be reconstructed when the tie hint is absent",
    );
}

#[test]
fn missing_higher_prefix_ties_are_rejected_as_bad_shape() {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        SortConfig::Uniform(UniformConfig {
            asc: true,
            strict: false,
        }),
    ))));
    let id = gadget.id();
    let two_keys = |values: &[i64]| {
        let mut table = spec("key", values, true);
        let second = Arc::new(Field::new("key2", DataType::Int8, false));
        table.cols.push((second, table.cols[0].1.clone()));
        let mut fields = table
            .cols
            .iter()
            .map(|(field, _)| field.clone())
            .collect::<Vec<_>>();
        fields.push(arithmetic::ACTIVATOR_FIELD.clone());
        table.schema = Schema::new(fields);
        table
    };
    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(id, TABLE_LABEL, two_keys(&[1, 2]))
        .with_table(id, ROTATED_INPUT_LABEL, two_keys(&[2, 1]))
        .build();
    let err = run_gadget_pipeline(harness)
        .expect_err("a public tie_0 cannot replace missing higher-prefix witnesses");
    assert!(matches!(
        err,
        ark_piop::errors::SnarkError::VerifierError(
            ark_piop::verifier::errors::VerifierError::VerifierInputShapeError(
                ark_piop::errors::InputShapeError::InputLengthMismatch {
                    expected: 2,
                    actual: 1
                }
            )
        )
    ));
}

#[test]
fn public_mask_preserves_existing_prefix_ties_and_metadata() {
    let mut harness = harness(&[1, 2, 3, 4], &[0, 0, 0, 0], true, false);
    let old = match harness.prover_ir.payload_for_node(&harness.node_id) {
        Some(PayloadStructure::GadgetPayload(payload)) => &payload[TIE_INDICATOR_LABEL],
        _ => panic!("missing test payload"),
    };
    let prefix = Arc::new(Field::new("tie_1", DataType::Boolean, false));
    let prefix_poly = old.tracked_col_by_ind(0).data_tracked_poly();
    let mut columns = old.tracked_polys();
    columns.insert(prefix.clone(), prefix_poly.clone());
    let schema = Schema::new_with_metadata(
        vec![
            old.schema_ref().unwrap().field(0).clone(),
            prefix.as_ref().clone(),
        ],
        [("test".to_string(), "preserved".to_string())].into(),
    );
    let table = arithmetic::table::TrackedTable::new(Some(schema), columns, old.log_size());
    let fixed = prepend_first_tie_indicator_prover(&mut harness.prover, Some(&table), 2);
    let twice = prepend_first_tie_indicator_prover(&mut harness.prover, Some(&fixed), 2);
    assert_eq!(twice.data_tracked_polys_indices().len(), 2);
    assert_eq!(twice.schema_ref().unwrap().fields().len(), 2);
    assert_eq!(twice.schema_ref().unwrap().metadata()["test"], "preserved");
    assert_eq!(
        twice
            .tracked_col_by_name("tie_1")
            .unwrap()
            .data_tracked_poly()
            .id(),
        prefix_poly.id(),
    );
}
