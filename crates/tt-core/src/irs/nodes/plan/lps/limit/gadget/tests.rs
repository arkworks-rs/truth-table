//! LIMIT cardinality tests, including verifier-only rejection of wrong prefixes.

use std::sync::Arc;

use arithmetic::table_oracle::TrackedTableOracle;
use ark_ff::{Fp64, MontBackend, MontConfig, PrimeField};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_expr::{Limit, LogicalPlanBuilder, lit};
use indexmap::IndexMap;

use super::{
    GadgetNode, INPUT_ACTIVATOR_LABEL, OUTPUT_ACTIVATOR_LABEL, checked_capacity,
    count_difference_prover, requires_all_input,
};
use crate::{
    irs::{nodes::Node, payloads::PayloadStructure},
    test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline},
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
struct TinyFieldConfig;
type TinyField = Fp64<MontBackend<TinyFieldConfig, 1>>;

const NV: usize = 2;

fn limit(fetch: Option<usize>) -> Limit {
    Limit {
        skip: None,
        fetch: fetch.map(|count| Box::new(lit(count as i64))),
        input: Arc::new(LogicalPlanBuilder::empty(false).build().unwrap()),
    }
}

fn harness(limit: &Limit, input: [u64; 4], prefix: usize) -> GadgetHarness<B> {
    assert!(prefix <= input.len());
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(limit.clone()))));
    let id = gadget.id();
    let spec = |name: &str, values: Vec<F>| {
        let field = Arc::new(Field::new(name, DataType::UInt64, false));
        TableSpec {
            schema: Schema::new(vec![field.as_ref().clone()]),
            log_size: NV,
            cols: vec![(field, values)],
            activator: None,
        }
    };
    let input_values = input.iter().copied().map(F::from).collect();
    // Mirror the plan's output.active = input.active * contiguous(prefix).
    let output_values = input
        .iter()
        .enumerate()
        .map(|(index, value)| F::from(if index < prefix { *value } else { 0 }))
        .collect();
    GadgetHarness::<B>::builder(4)
        .with_gadget(gadget)
        .with_table(
            id,
            INPUT_ACTIVATOR_LABEL,
            spec("input_activator", input_values),
        )
        .with_table(
            id,
            OUTPUT_ACTIVATOR_LABEL,
            spec("output_activator", output_values),
        )
        .build()
}

/// Prove only true claims for the supplied (possibly wrong) output. Bypass the
/// honest LIMIT prover and let the real verifier derive its required claims.
/// Except for the test that deliberately lies about the committed count, proof
/// construction succeeds, so rejection cannot come from a local honest-prover
/// assertion.
fn verify_supplied_prefix(
    limit: &Limit,
    input: [u64; 4],
    prefix: usize,
    reported_output_count: u64,
    include_input_boolean_claim: bool,
) -> SnarkResult<()> {
    let mut harness = harness(limit, input, prefix);
    let Some(PayloadStructure::GadgetPayload(tables)) = harness
        .prover_ir
        .payload_for_node(&harness.node_id)
        .cloned()
    else {
        panic!("test harness must provide activators");
    };
    let input_act = tables[INPUT_ACTIVATOR_LABEL]
        .tracked_col_by_ind(0)
        .data_tracked_poly();
    let output_act = tables[OUTPUT_ACTIVATOR_LABEL]
        .tracked_col_by_ind(0)
        .data_tracked_poly();
    let reported_output_count = F::from(reported_output_count);
    let committed_count = harness
        .prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(0, vec![reported_output_count]))?;
    if include_input_boolean_claim {
        let input_boolean = &input_act * &input_act.sub_scalar_poly(F::from(1u64));
        harness
            .prover
            .add_mv_zerocheck_claim(input_boolean.id())
            .expect("the supplied Boolean identity is true");
    }
    let count_difference = count_difference_prover(&output_act, &committed_count)?;
    harness
        .prover
        .add_mv_sumcheck_claim(count_difference.id(), F::from(0u64))?;
    if requires_all_input(limit, reported_output_count, NV).unwrap_or(false) {
        // Supply an unrelated true zerocheck, not the required input-output
        // relation. The verifier must enforce its own polynomial identity.
        let fake_omitted_rows = output_act.mul_scalar_poly(F::from(0u64));
        harness
            .prover
            .add_mv_zerocheck_claim(fake_omitted_rows.id())
            .expect("the supplied zero identity is true");
    }
    let proof = harness
        .prover
        .build_proof()
        .expect("true sum claims must produce a proof");
    harness.verifier.set_proof(proof);
    let mut verifier_tables = IndexMap::new();
    for (label, table) in tables {
        let mut oracles = IndexMap::new();
        for (field, poly) in table.tracked_polys_iter() {
            let oracle = harness
                .verifier
                .track_mv_com_by_id(poly.id())
                .expect("the proof includes every committed activator");
            oracles.insert(field, oracle);
        }
        verifier_tables.insert(label, TrackedTableOracle::new(table.schema(), oracles, NV));
    }
    harness.verifier_ir.set_payload_for_node(
        harness.node_id,
        Some(PayloadStructure::GadgetPayload(verifier_tables)),
    );
    harness.gadget.verify(
        &mut harness.verifier,
        &mut harness.verifier_ir,
        harness.node_id,
    )?;
    harness.verifier.verify()?;
    Ok(())
}

#[test]
fn sparse_limit_honest_prefix_verifies() {
    run_gadget_pipeline(harness(&limit(Some(2)), [1, 0, 1, 1], 3)).unwrap();
}

#[test]
fn output_count_is_a_transcript_bound_constant() {
    let mut harness = harness(&limit(Some(2)), [1, 0, 1, 1], 3);
    harness
        .gadget
        .prove(&mut harness.prover, &mut harness.prover_ir, harness.node_id)
        .unwrap();
    let proof = harness.prover.build_proof().unwrap();
    assert!(proof.miscellaneous_field_elements.is_empty());
    assert!(
        proof
            .mv_pcs_subproof
            .unique_constants
            .values()
            .any(|value| *value == F::from(2u64))
    );
}

#[test]
fn oversized_limit_keeps_all_active_rows() {
    run_gadget_pipeline(harness(&limit(Some(10)), [1, 0, 1, 1], 4)).unwrap();
}

#[test]
fn zero_limit_selects_no_rows() {
    run_gadget_pipeline(harness(&limit(Some(0)), [1, 0, 1, 1], 0)).unwrap();
}

#[test]
fn absent_fetch_keeps_all_active_rows() {
    run_gadget_pipeline(harness(&limit(None), [1, 0, 1, 1], 4)).unwrap();
}

#[test]
fn empty_input_has_empty_output() {
    run_gadget_pipeline(harness(&limit(Some(2)), [0, 0, 0, 0], 4)).unwrap();
}

#[test]
fn supplied_correct_prefix_verifies() {
    verify_supplied_prefix(&limit(Some(2)), [1, 0, 1, 1], 3, 2, true).unwrap();
}

#[test]
fn shorter_prefix_rejected_by_verifier() {
    assert!(verify_supplied_prefix(&limit(Some(2)), [1, 0, 1, 1], 1, 1, true).is_err());
}

#[test]
fn longer_prefix_rejected_by_verifier() {
    assert!(verify_supplied_prefix(&limit(Some(2)), [1, 0, 1, 1], 4, 3, true).is_err());
}

#[test]
fn false_output_count_cannot_justify_shorter_prefix() {
    assert!(verify_supplied_prefix(&limit(Some(2)), [1, 0, 1, 1], 1, 2, true).is_err());
}

#[test]
fn non_boolean_input_cannot_fake_the_fetch_count() {
    // Without the local Boolean check, one physical value `2` has sum two and
    // could satisfy LIMIT 2 even though it is not two active rows. Construct
    // exactly that old-protocol proof (sumcheck only); the hardened verifier
    // additionally requires a Boolean zerocheck and rejects it.
    assert!(verify_supplied_prefix(&limit(Some(2)), [2, 0, 0, 0], 1, 2, false).is_err());
}

#[test]
fn oversized_limit_cannot_omit_rows() {
    assert!(verify_supplied_prefix(&limit(Some(10)), [1, 0, 1, 1], 3, 2, true).is_err());
}

#[test]
fn zero_and_absent_fetch_are_enforced_by_verifier() {
    assert!(verify_supplied_prefix(&limit(Some(0)), [1, 0, 1, 1], 1, 1, true).is_err());
    assert!(verify_supplied_prefix(&limit(None), [1, 0, 1, 1], 3, 2, true).is_err());
}

#[test]
fn offset_and_negative_fetch_fail_closed() {
    let mut with_offset = limit(Some(2));
    with_offset.skip = Some(Box::new(lit(1i64)));
    assert!(run_gadget_pipeline(harness(&with_offset, [1, 1, 1, 1], 2)).is_err());

    let mut negative_fetch = limit(Some(2));
    negative_fetch.fetch = Some(Box::new(lit(-1i64)));
    assert!(run_gadget_pipeline(harness(&negative_fetch, [1, 1, 1, 1], 2)).is_err());
}

#[test]
fn output_count_must_be_bounded_without_wrap() {
    assert!(requires_all_input(&limit(Some(2)), F::from(5u64), NV).is_err());
    assert!(requires_all_input(&limit(Some(2)), -F::from(1u64), NV).is_err());
    assert!(checked_capacity::<F>(F::MODULUS_BIT_SIZE as usize).is_err());
    assert_eq!(checked_capacity::<TinyField>(4).unwrap(), 16);
    assert!(checked_capacity::<TinyField>(5).is_err());
}
