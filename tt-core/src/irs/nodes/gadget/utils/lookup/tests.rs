use std::collections::HashMap;
use std::sync::Arc;

use arithmetic::ACTIVATOR_FIELD;
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::{SnarkError, SnarkResult};
use ark_piop::test_utils::test_prelude;
use ark_piop::{DefaultSnarkBackend, SnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use indexmap::IndexMap;

use super::{GadgetNode, INCLUDED_LABEL, SUPER_LABEL, SUPER_MULTIPLICITIES_LABEL};
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

fn multiplicity_map<F: PrimeField>(values: &[F], activator: Option<&[F]>) -> HashMap<F, u64> {
    let mut mults = HashMap::<F, u64>::new();
    if let Some(sel) = activator {
        for (i, &val) in values.iter().enumerate() {
            if sel[i] == F::zero() {
                continue;
            }
            *mults.entry(val).or_insert(0) += 1;
        }
    } else {
        for &val in values {
            *mults.entry(val).or_insert(0) += 1;
        }
    }
    mults
}

fn calc_inclusion_multiplicity<F: PrimeField>(
    included_values: &[F],
    included_activator: Option<&[F]>,
    super_values: &[F],
    super_activator: Option<&[F]>,
) -> Vec<F> {
    let mut included_mults = multiplicity_map(included_values, included_activator);
    let mut super_mults = Vec::with_capacity(super_values.len());

    for (i, &val) in super_values.iter().enumerate() {
        if let Some(sel) = super_activator
            && sel[i] == F::zero()
        {
            super_mults.push(F::zero());
            continue;
        }

        if let Some(&count) = included_mults.get(&val) {
            super_mults.push(F::from(count));
            included_mults.insert(val, 0);
        } else {
            super_mults.push(F::zero());
        }
    }

    super_mults
}

fn build_tracked_table(
    prover: &mut ArgProver<Backend>,
    prefix: &str,
    columns: &[Vec<<Backend as SnarkBackend>::F>],
    activator: Option<Vec<<Backend as SnarkBackend>::F>>,
) -> TrackedTable<Backend> {
    assert!(!columns.is_empty(), "table must have at least one column");
    let len = columns[0].len();
    for column in columns.iter().skip(1) {
        assert_eq!(column.len(), len, "all columns must have equal length");
    }
    if let Some(ref sel) = activator {
        assert_eq!(sel.len(), len, "activator length must match columns");
    }

    let log_size = log_size_from_len(len);
    let mut fields = columns
        .iter()
        .enumerate()
        .map(|(idx, _)| Field::new(format!("{prefix}_{idx}"), DataType::UInt64, false))
        .collect::<Vec<_>>();
    if activator.is_some() {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
    }
    let schema = Schema::new(fields);

    let mut tracked_polys = IndexMap::new();
    for (idx, column) in columns.iter().enumerate() {
        let mle = MLE::from_evaluations_vec(log_size, column.clone());
        let tracked_poly = prover.track_and_commit_mat_mv_poly(&mle).unwrap();
        tracked_polys.insert(schema.fields()[idx].clone(), tracked_poly);
    }
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

fn run_lookup_roundtrip(
    included_cols: Vec<Vec<<Backend as SnarkBackend>::F>>,
    included_activator: Option<Vec<<Backend as SnarkBackend>::F>>,
    super_col: Vec<<Backend as SnarkBackend>::F>,
    super_activator: Option<Vec<<Backend as SnarkBackend>::F>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();

    let included_table = build_tracked_table(
        &mut prover,
        "inc",
        &included_cols,
        included_activator.clone(),
    );
    let super_table = build_tracked_table(
        &mut prover,
        "sup",
        &[super_col.clone()],
        super_activator.clone(),
    );

    let multiplicity_cols = included_cols
        .iter()
        .map(|col| {
            calc_inclusion_multiplicity(
                col,
                included_activator.as_deref(),
                &super_col,
                super_activator.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    let multiplicities_table = build_tracked_table(&mut prover, "mult", &multiplicity_cols, None);

    let gadget_node = Arc::new(GadgetNode::<Backend>::new());
    let root = Arc::new(Node::Gadget(gadget_node));
    let tree = Tree::new_from_root(root.clone());

    let mut gadget_payload = IndexMap::new();
    gadget_payload.insert(INCLUDED_LABEL.to_string(), included_table.clone());
    gadget_payload.insert(SUPER_LABEL.to_string(), super_table.clone());
    gadget_payload.insert(
        SUPER_MULTIPLICITIES_LABEL.to_string(),
        multiplicities_table.clone(),
    );

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

    let included_oracle = tracked_table_to_oracle(&included_table, &mut verifier);
    let super_oracle = tracked_table_to_oracle(&super_table, &mut verifier);
    let multiplicities_oracle = tracked_table_to_oracle(&multiplicities_table, &mut verifier);

    let mut gadget_payload = IndexMap::new();
    gadget_payload.insert(INCLUDED_LABEL.to_string(), included_oracle);
    gadget_payload.insert(SUPER_LABEL.to_string(), super_oracle);
    gadget_payload.insert(
        SUPER_MULTIPLICITIES_LABEL.to_string(),
        multiplicities_oracle,
    );

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
fn gadget_lookup_completeness_no_activator() {
    let included_col = evals_from_u64(&[25, 7, 7, 2]);
    let super_col = evals_from_u64(&[25, 7, 7, 2]);
    run_lookup_roundtrip(vec![included_col], None, super_col, None).unwrap();
}

#[test]
fn gadget_lookup_completeness_with_activators() {
    let included_col = evals_from_u64(&[25, 7, 7, 200]);
    let included_activator = evals_from_u64(&[0, 0, 1, 0]);
    let super_col = evals_from_u64(&[25, 7, 7, 2]);
    let super_activator = evals_from_u64(&[0, 1, 0, 1]);
    run_lookup_roundtrip(
        vec![included_col],
        Some(included_activator),
        super_col,
        Some(super_activator),
    )
    .unwrap();
}

#[test]
fn gadget_lookup_soundness_rejects_missing_value() {
    let included_col = evals_from_u64(&[25, 7, 8, 2]);
    let super_col = evals_from_u64(&[25, 7, 7, 2]);
    let err = run_lookup_roundtrip(vec![included_col], None, super_col, None).unwrap_err();
    assert_soundness_error(err);
}
