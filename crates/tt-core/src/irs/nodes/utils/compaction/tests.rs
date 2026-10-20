use std::sync::Arc;

use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, prover::structs::proof::SNARKProof, types::TrackerID,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{GadgetNode, INPUT_LABEL, OUTPUT_LABEL};
use crate::{
    irs::nodes::Node,
    test_utils::gadget_harness::{
        GadgetHarness, TableSpec, run_gadget_pipeline, run_gadget_pipeline_to_verifier,
    },
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn table(values: [u64; 4], active: [u64; 4]) -> TableSpec<F> {
    let field = Arc::new(Field::new("value", DataType::UInt64, false));
    TableSpec {
        schema: Schema::new(vec![field.as_ref().clone()]),
        log_size: 2,
        cols: vec![(field, values.into_iter().map(F::from).collect())],
        activator: Some(active.into_iter().map(F::from).collect()),
    }
}

fn harness_with_input(
    input_values: [u64; 4],
    input_active: [u64; 4],
    output_values: [u64; 4],
    output_active: [u64; 4],
) -> GadgetHarness<B> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(true))));
    let id = gadget.id();
    GadgetHarness::<B>::builder(6)
        .with_gadget(gadget)
        .with_table(id, INPUT_LABEL, table(input_values, input_active))
        .with_table(id, OUTPUT_LABEL, table(output_values, output_active))
        .build()
}

fn harness(output_values: [u64; 4], output_active: [u64; 4]) -> GadgetHarness<B> {
    harness_with_input([3, 0, 8, 0], [1, 0, 1, 0], output_values, output_active)
}

fn committed_prefix_count_id(proof: &SNARKProof<B>, expected: F) -> TrackerID {
    let candidates = proof
        .mv_pcs_subproof
        .constant_map
        .iter()
        .filter_map(|(tracker_id, constant_id)| {
            let value = proof.mv_pcs_subproof.unique_constants.get(constant_id)?;
            let num_vars = proof.mv_pcs_subproof.constant_num_vars.get(tracker_id)?;
            (*value == expected && *num_vars == 0).then_some(*tracker_id)
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 1);
    candidates[0]
}

#[test]
fn contiguous_permutation_is_accepted() {
    run_gadget_pipeline(harness([8, 3, 0, 0], [1, 1, 0, 0])).unwrap();
}

#[test]
fn scattered_permutation_is_rejected() {
    // Bool and Perm hold; only the gap between the active rows is wrong.
    assert!(run_gadget_pipeline(harness([8, 0, 3, 0], [1, 0, 1, 0])).is_err());
}

#[test]
fn empty_active_bag_accepts_empty_prefix() {
    run_gadget_pipeline(harness_with_input(
        [3, 5, 8, 13],
        [0, 0, 0, 0],
        [13, 8, 5, 3],
        [0, 0, 0, 0],
    ))
    .unwrap();
}

#[test]
fn fully_active_bag_accepts_full_prefix() {
    run_gadget_pipeline(harness_with_input(
        [3, 5, 8, 13],
        [1, 1, 1, 1],
        [13, 8, 5, 3],
        [1, 1, 1, 1],
    ))
    .unwrap();
}

#[test]
fn tampered_prefix_count_is_rejected() {
    let result = run_gadget_pipeline_to_verifier(harness([8, 3, 0, 0], [1, 1, 0, 0]), |proof| {
        let count_id = committed_prefix_count_id(proof, F::from(2u64));
        let constant_id = proof.mv_pcs_subproof.constant_map[&count_id];
        let count = proof
            .mv_pcs_subproof
            .unique_constants
            .get_mut(&constant_id)
            .unwrap();
        assert_eq!(*count, F::from(2u64));
        *count = F::from(1u64);
    })
    .unwrap();
    assert!(result.is_err());
}

#[test]
fn non_scalar_prefix_count_is_rejected() {
    let result = run_gadget_pipeline_to_verifier(harness([8, 3, 0, 0], [1, 1, 0, 0]), |proof| {
        let count_id = committed_prefix_count_id(proof, F::from(2u64));
        let constant_id = proof.mv_pcs_subproof.constant_map[&count_id];
        assert_eq!(
            proof.mv_pcs_subproof.unique_constants[&constant_id],
            F::from(2u64)
        );
        proof.mv_pcs_subproof.constant_num_vars.insert(count_id, 1);
    })
    .unwrap();
    assert!(result.is_err());
}
