use std::sync::Arc;

use arithmetic::ACTIVATOR_FIELD;
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::{SnarkError, SnarkResult};
use ark_piop::test_utils::test_prelude;
use ark_piop::{DefaultSnarkBackend, SnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use indexmap::IndexMap;

use super::{GadgetNode, INPUT_LABEL};
use crate::irs::nodes::Node;
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;
use crate::prover::passes::gadget_initialization::GadgetInitializationPass as ProverGadgetInitializationPass;
use crate::prover::passes::proving::ProvingPass;
use crate::prover::passes::virtualization::VirtualizationPass as ProverVirtualizationPass;
use crate::verifier::passes::gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass;
use crate::verifier::passes::verify::VerifyPass;
use crate::verifier::passes::virtualization::VirtualizationPass as VerifierVirtualizationPass;

type Backend = DefaultSnarkBackend;

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

fn evals_from_u64(values: &[u64]) -> Vec<<Backend as SnarkBackend>::F> {
    values
        .iter()
        .copied()
        .map(<Backend as SnarkBackend>::F::from)
        .collect()
}

fn log_size_from_len(len: usize) -> usize {
    assert!(len.is_power_of_two(), "length must be a power of two");
    len.trailing_zeros() as usize
}

fn build_tracked_table(
    prover: &mut ArgProver<Backend>,
    prefix: &str,
    column: Vec<<Backend as SnarkBackend>::F>,
    activator: Option<Vec<<Backend as SnarkBackend>::F>>,
) -> TrackedTable<Backend> {
    let len = column.len();
    if let Some(ref sel) = activator {
        assert_eq!(sel.len(), len, "activator length must match column");
    }
    let log_size = log_size_from_len(len);

    let mut fields = vec![Field::new(format!("{prefix}_0"), DataType::UInt64, false)];
    if activator.is_some() {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
    }
    let schema = Schema::new(fields);

    let mut tracked_polys = IndexMap::new();
    let mle = MLE::from_evaluations_vec(log_size, column);
    let tracked_poly = prover.track_and_commit_mat_mv_poly(&mle).unwrap();
    tracked_polys.insert(schema.fields()[0].clone(), tracked_poly);

    if let Some(sel) = activator {
        let mle = MLE::from_evaluations_vec(log_size, sel);
        let tracked_poly = prover.track_and_commit_mat_mv_poly(&mle).unwrap();
        let activator_idx = schema.fields().len() - 1;
        tracked_polys.insert(schema.fields()[activator_idx].clone(), tracked_poly);
    }

    TrackedTable::new(Some(schema), tracked_polys, log_size)
}

fn tracked_table_to_oracle(
    table: &TrackedTable<Backend>,
    verifier: &mut ArgVerifier<Backend>,
) -> TrackedTableOracle<Backend> {
    let mut tracked_oracles = IndexMap::new();
    for (field, poly) in table.tracked_polys_iter() {
        let oracle = verifier.track_mv_com_by_id(poly.id()).unwrap();
        tracked_oracles.insert(field.clone(), oracle);
    }
    TrackedTableOracle::new(table.schema(), tracked_oracles, table.log_size())
}

fn run_nodup_roundtrip(
    values: Vec<<Backend as SnarkBackend>::F>,
    activator: Option<Vec<<Backend as SnarkBackend>::F>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();
    let input_table = build_tracked_table(&mut prover, "col", values, activator);

    let gadget_node = Arc::new(GadgetNode::<Backend>::default());
    let root = Arc::new(Node::Gadget(gadget_node));
    let tree = Tree::new_from_root(root.clone());

    let gadget_payload = IndexMap::from([(INPUT_LABEL.to_string(), input_table.clone())]);
    let mut prover_payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    prover_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let tracked_ir = crate::prover::irs::TrackedIr::new(tree.clone(), prover_payloads);

    let virtualization_pass = ProverVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass = ProverGadgetInitializationPass::<Backend>::new(gadget_ir_view);
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    let proving_ir_view = crate::prover::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let proving_pass = ProvingPass::<Backend>::new(prover.clone(), proving_ir_view);
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
    proving_pass.take_result()?;

    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let input_oracle = tracked_table_to_oracle(&input_table, &mut verifier);
    let gadget_payload = IndexMap::from([(INPUT_LABEL.to_string(), input_oracle)]);
    let mut verifier_payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    verifier_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let tracked_ir = crate::verifier::irs::TrackedIr::new(tree, verifier_payloads);

    let virtualization_pass = VerifierVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::verifier::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass =
        VerifierGadgetInitializationPass::<Backend>::new(gadget_ir_view);
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    let verify_ir_view = crate::verifier::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let verify_pass = VerifyPass::<Backend>::new(verifier.clone(), verify_ir_view);
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
    verify_pass.take_result()?;

    verifier.verify()?;
    Ok(())
}

#[test]
fn gadget_nodup_completeness_all_active() {
    let values = evals_from_u64(&[4, 7, 1, 20, 18, 2, 12, 3]);
    let activator = evals_from_u64(&[1, 1, 1, 1, 1, 1, 1, 1]);
    run_nodup_roundtrip(values, Some(activator)).unwrap();
}

#[test]
fn gadget_nodup_completeness_inactive_duplicate() {
    let values = evals_from_u64(&[4, 7, 1, 20, 18, 2, 12, 4]);
    let activator = evals_from_u64(&[1, 1, 1, 1, 1, 1, 1, 0]);
    run_nodup_roundtrip(values, Some(activator)).unwrap();
}

#[test]
fn gadget_nodup_soundness_rejects_duplicate() {
    let values = evals_from_u64(&[4, 7, 1, 20, 18, 2, 12, 4]);
    let activator = evals_from_u64(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let err = run_nodup_roundtrip(values, Some(activator)).unwrap_err();
    assert_soundness_error(err);
}
