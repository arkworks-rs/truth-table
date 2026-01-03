use std::sync::Arc;

use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::{SnarkError, SnarkResult};
use ark_piop::test_utils::test_prelude;
use ark_piop::{DefaultSnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use indexmap::IndexMap;

use super::{FXS_LABEL, GXS_LABEL, GadgetNode, MFXS_LABEL, MGXS_LABEL};
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
    columns: &[Vec<<Backend as SnarkBackend>::F>],
) -> TrackedTable<Backend> {
    assert!(!columns.is_empty(), "table must have at least one column");
    let len = columns[0].len();
    for column in columns.iter().skip(1) {
        assert_eq!(column.len(), len, "all columns must have equal length");
    }
    let log_size = log_size_from_len(len);
    let fields = columns
        .iter()
        .enumerate()
        .map(|(idx, _)| Field::new(format!("{prefix}_{idx}"), DataType::UInt64, false))
        .collect::<Vec<_>>();
    let schema = Schema::new(fields);
    let mut tracked_polys = IndexMap::new();
    for (idx, column) in columns.iter().enumerate() {
        let mle = MLE::from_evaluations_vec(log_size, column.clone());
        let tracked_poly = prover.track_and_commit_mat_mv_poly(&mle).unwrap();
        tracked_polys.insert(schema.fields()[idx].clone(), tracked_poly);
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

fn run_keyed_sumcheck_roundtrip(
    fxs_cols: Vec<Vec<<Backend as SnarkBackend>::F>>,
    gxs_cols: Vec<Vec<<Backend as SnarkBackend>::F>>,
    mfxs_cols: Option<Vec<Vec<<Backend as SnarkBackend>::F>>>,
    mgxs_cols: Option<Vec<Vec<<Backend as SnarkBackend>::F>>>,
) -> SnarkResult<()> {
    if let Some(mfxs) = mfxs_cols.as_ref() {
        assert_eq!(mfxs.len(), fxs_cols.len(), "mfxs must align with fxs");
    }
    if let Some(mgxs) = mgxs_cols.as_ref() {
        assert_eq!(mgxs.len(), gxs_cols.len(), "mgxs must align with gxs");
    }

    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();
    let fxs_table = build_tracked_table(&mut prover, "fx", &fxs_cols);
    let gxs_table = build_tracked_table(&mut prover, "gx", &gxs_cols);
    let mfxs_table = mfxs_cols
        .as_ref()
        .map(|cols| build_tracked_table(&mut prover, "mfx", cols));
    let mgxs_table = mgxs_cols
        .as_ref()
        .map(|cols| build_tracked_table(&mut prover, "mgx", cols));

    let gadget_node = Arc::new(GadgetNode::<Backend>::new());
    let root = Arc::new(Node::Gadget(gadget_node));
    let tree = Tree::new_from_root(root.clone());

    let mut gadget_payload = IndexMap::new();
    gadget_payload.insert(FXS_LABEL.to_string(), fxs_table.clone());
    gadget_payload.insert(GXS_LABEL.to_string(), gxs_table.clone());
    if let Some(table) = mfxs_table.clone() {
        gadget_payload.insert(MFXS_LABEL.to_string(), table);
    }
    if let Some(table) = mgxs_table.clone() {
        gadget_payload.insert(MGXS_LABEL.to_string(), table);
    }

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

    let fxs_oracle = tracked_table_to_oracle(&fxs_table, &mut verifier);
    let gxs_oracle = tracked_table_to_oracle(&gxs_table, &mut verifier);
    let mfxs_oracle = mfxs_table
        .as_ref()
        .map(|table| tracked_table_to_oracle(table, &mut verifier));
    let mgxs_oracle = mgxs_table
        .as_ref()
        .map(|table| tracked_table_to_oracle(table, &mut verifier));

    let mut gadget_payload = IndexMap::new();
    gadget_payload.insert(FXS_LABEL.to_string(), fxs_oracle);
    gadget_payload.insert(GXS_LABEL.to_string(), gxs_oracle);
    if let Some(table) = mfxs_oracle {
        gadget_payload.insert(MFXS_LABEL.to_string(), table);
    }
    if let Some(table) = mgxs_oracle {
        gadget_payload.insert(MGXS_LABEL.to_string(), table);
    }

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
fn gadget_keyed_sumcheck_completeness_single_column_no_multiplicity() {
    let fxs_cols = vec![evals_from_u64(&[1, 2, 3, 4])];
    let gxs_cols = vec![evals_from_u64(&[4, 2, 3, 1])];
    run_keyed_sumcheck_roundtrip(fxs_cols, gxs_cols, None, None).unwrap();
}

#[test]
fn gadget_keyed_sumcheck_completeness_with_multiplicity_columns() {
    let fxs_cols = vec![evals_from_u64(&[1, 2, 3, 4]), evals_from_u64(&[5, 6, 7, 8])];
    let gxs_cols = vec![evals_from_u64(&[2, 1, 4, 3]), evals_from_u64(&[8, 7, 6, 5])];
    let mfxs_cols = vec![evals_from_u64(&[1, 1, 1, 1]), evals_from_u64(&[1, 1, 1, 1])];
    let mgxs_cols = vec![evals_from_u64(&[1, 1, 1, 1]), evals_from_u64(&[1, 1, 1, 1])];
    run_keyed_sumcheck_roundtrip(fxs_cols, gxs_cols, Some(mfxs_cols), Some(mgxs_cols)).unwrap();
}

#[test]
fn gadget_keyed_sumcheck_soundness_rejects_mismatch() {
    let fxs_cols = vec![evals_from_u64(&[1, 2, 3, 4])];
    let gxs_cols = vec![evals_from_u64(&[1, 2, 3, 5])];
    let err = run_keyed_sumcheck_roundtrip(fxs_cols, gxs_cols, None, None).unwrap_err();
    assert_soundness_error(err);
}
