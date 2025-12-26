use super::*;
use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::{SnarkError, SnarkResult};
use ark_piop::prover::ArgProver;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::test_utils::test_prelude;
use ark_piop::verifier::ArgVerifier;
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field};
use indexmap::IndexMap;

use crate::irs::nodes::Node;
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;
use crate::prover::passes::gadget_initialization::GadgetInitializationPass as ProverGadgetInitializationPass;
use crate::prover::passes::virtualization::VirtualizationPass as ProverVirtualizationPass;
use crate::verifier::passes::gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass;
use crate::verifier::passes::virtualization::VirtualizationPass as VerifierVirtualizationPass;

type Backend = DefaultSnarkBackend;
const LOG_SIZE: usize = 2;

fn assert_soundness_error(err: SnarkError) {
    #[cfg(feature = "honest-prover")]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::ProverError(
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
            ark_piop::errors::SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(_)
            )
        ));
    }
}

fn evals_from_i64(evals: &[i64]) -> Vec<<Backend as SnarkBackend>::F> {
    evals
        .iter()
        .map(|value| {
            if *value < 0 {
                -<Backend as SnarkBackend>::F::from((-*value) as u64)
            } else {
                <Backend as SnarkBackend>::F::from(*value as u64)
            }
        })
        .collect()
}

fn tracked_poly_from_evals(
    prover: &mut ArgProver<Backend>,
    evals: Vec<<Backend as SnarkBackend>::F>,
) -> TrackedPoly<Backend> {
    let mle = MLE::from_evaluations_vec(LOG_SIZE, evals);
    prover.track_and_commit_mat_mv_poly(&mle).unwrap()
}

fn prove_gadgets(
    prover: &mut ArgProver<Backend>,
    gadget_ready_ir: &mut crate::prover::irs::GadgetReadyIr<Backend>,
) -> SnarkResult<()> {
    let nodes: Vec<_> = gadget_ready_ir.tree().arena().values().cloned().collect();
    for node in nodes {
        if let Node::Gadget(gadget_node) = node.as_ref() {
            gadget_node.prove(prover, gadget_ready_ir, node.id())?;
        }
    }
    Ok(())
}

fn verify_gadgets(
    verifier: &mut ArgVerifier<Backend>,
    gadget_ready_ir: &mut crate::verifier::irs::GadgetReadyIr<Backend>,
) -> SnarkResult<()> {
    let nodes: Vec<_> = gadget_ready_ir.tree().arena().values().cloned().collect();
    for node in nodes {
        if let Node::Gadget(gadget_node) = node.as_ref() {
            gadget_node.verify(verifier, gadget_ready_ir, node.id())?;
        }
    }
    Ok(())
}

fn end_to_end_bin_geq_prove_and_verify(
    left: &[i64],
    right: &[i64],
    output: &[i64],
    activator: &[i64],
) -> SnarkResult<()> {
    // Keep the test vectors consistent with the log size of this gadget (2^LOG_SIZE rows).
    let expected_len = 1 << LOG_SIZE;
    debug_assert_eq!(left.len(), expected_len);
    debug_assert_eq!(right.len(), expected_len);
    debug_assert_eq!(output.len(), expected_len);
    debug_assert_eq!(activator.len(), expected_len);

    // Set up a fresh prover/verifier pair with shared transcript parameters.
    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();

    // Commit prover polynomials for the left/right operands, output bit, and shared activator.
    let left_poly = tracked_poly_from_evals(&mut prover, evals_from_i64(left));
    let right_poly = tracked_poly_from_evals(&mut prover, evals_from_i64(right));
    let output_poly = tracked_poly_from_evals(&mut prover, evals_from_i64(output));
    let shared_activator = tracked_poly_from_evals(&mut prover, evals_from_i64(activator));

    // Wrap each tracked polynomial as a single-column tracked table with the same activator.
    let left_table = TrackedTable::single_column_with_activator(
        Arc::new(Field::new("left", DataType::Int8, false)),
        left_poly.clone(),
        Some(shared_activator.clone()),
    );
    let right_table = TrackedTable::single_column_with_activator(
        Arc::new(Field::new("right", DataType::Int8, false)),
        right_poly.clone(),
        Some(shared_activator.clone()),
    );
    let output_table = TrackedTable::single_column_with_activator(
        Arc::new(Field::new("output", DataType::Int8, false)),
        output_poly.clone(),
        Some(shared_activator.clone()),
    );

    // Build a BinQeq gadget node and a minimal tree with that gadget as the root.
    let bin_node = Arc::new(BinGeqNode::<Backend>::new());
    let root = Arc::new(Node::Gadget(bin_node.clone()));
    let tree = Tree::new_from_root(root.clone());

    // Seed the prover IR with payloads for every node so virtualization doesn't miss IDs.
    let gadget_payload = IndexMap::from([
        (LEFT_INPUT_LABEL.to_string(), left_table.clone()),
        (RIGHT_INPUT_LABEL.to_string(), right_table.clone()),
        (OUTPUT_LABEL.to_string(), output_table.clone()),
    ]);
    let mut payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let tracked_ir = crate::prover::irs::TrackedIr::new(tree.clone(), payloads);

    // Run the virtualization pass so the gadget can inject any virtual witnesses.
    let virtualization_pass = ProverVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);

    // Run gadget initialization to produce the child sign gadget payloads.
    let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass = ProverGadgetInitializationPass::<Backend>::new(gadget_ir_view);
    let mut gadget_ready_ir =
        virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    // Prove every gadget in post-order, so children are satisfied before parents.
    prove_gadgets(&mut prover, &mut gadget_ready_ir)?;

    // Finalize the prover transcript into a proof that the verifier can consume.
    let proof = prover.build_proof()?;

    // Move the proof into the verifier transcript state.
    verifier.set_proof(proof);

    // Track commitments in a deterministic order to keep tracker IDs aligned.
    let mut tracked_ids = vec![
        left_poly.id(),
        right_poly.id(),
        output_poly.id(),
        shared_activator.id(),
    ];
    tracked_ids.sort();
    let mut oracle_by_id = IndexMap::new();
    for id in tracked_ids {
        oracle_by_id.insert(id, verifier.track_mv_com_by_id(id)?);
    }

    // Extract tracked oracles for each input column.
    let left_oracle = oracle_by_id[&left_poly.id()].clone();
    let right_oracle = oracle_by_id[&right_poly.id()].clone();
    let output_oracle = oracle_by_id[&output_poly.id()].clone();
    let activator_oracle = oracle_by_id[&shared_activator.id()].clone();

    // Build the verifier payloads that mirror the prover's tracked tables.
    let mut verifier_payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    verifier_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(IndexMap::from([
            (
                LEFT_INPUT_LABEL.to_string(),
                TrackedTableOracle::single_column_with_activator(
                    Arc::new(Field::new("left", DataType::Int8, false)),
                    left_oracle,
                    Some(activator_oracle.clone()),
                ),
            ),
            (
                RIGHT_INPUT_LABEL.to_string(),
                TrackedTableOracle::single_column_with_activator(
                    Arc::new(Field::new("right", DataType::Int8, false)),
                    right_oracle,
                    Some(activator_oracle.clone()),
                ),
            ),
            (
                OUTPUT_LABEL.to_string(),
                TrackedTableOracle::single_column_with_activator(
                    Arc::new(Field::new("output", DataType::Int8, false)),
                    output_oracle,
                    Some(activator_oracle),
                ),
            ),
        ]))),
    );

    // Re-run virtualization and gadget initialization on the verifier side.
    let tracked_ir = crate::verifier::irs::TrackedIr::new(tree, verifier_payloads);
    let virtualization_pass = VerifierVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::verifier::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass =
        VerifierGadgetInitializationPass::<Backend>::new(gadget_ir_view);
    let mut gadget_ready_ir =
        virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    // Verify every gadget against the proof transcript.
    verify_gadgets(&mut verifier, &mut gadget_ready_ir)?;

    // Run the global verifier checks to finish the roundtrip.
    verifier.verify()?;
    Ok(())
}

#[test]
fn completeness_bin_geq_roundtrip() {
    let activator = [1, 1, 1, 1];
    end_to_end_bin_geq_prove_and_verify(
        &[20, -3, -4, -5],
        &[20, 2, 3, 4],
        &[1, 0, 0, 0],
        &activator,
    )
    .unwrap();
    end_to_end_bin_geq_prove_and_verify(&[0, 5, -2, 7], &[0, 6, -3, 10], &[1, 0, 1, 0], &activator)
        .unwrap();
}

#[test]
fn soundness_bin_geq_rejects_false_positive() {
    let activator = [1, 1, 1, 1];
    let err = end_to_end_bin_geq_prove_and_verify(
        &[1, 2, 3, 4],
        &[0, 3, 3, 5],
        &[1, 1, 1, 0],
        &activator,
    )
    .unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn soundness_bin_geq_rejects_false_negative() {
    let activator = [1, 1, 1, 1];
    let err = end_to_end_bin_geq_prove_and_verify(
        &[4, 2, 1, 0],
        &[4, 1, 2, 0],
        &[0, 1, 0, 1],
        &activator,
    )
    .unwrap_err();
    assert_soundness_error(err);
}
