use std::sync::Arc;

use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::{SnarkError, SnarkResult};
use ark_piop::test_utils::test_prelude;
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use indexmap::IndexMap;

use super::{INPUT_LABEL, Sign, SignNode};
use crate::irs::nodes::{IsGadgetNode, Node};
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;
use crate::prover::irs::GadgetReadyIr as ProverGadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

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

fn run_sign_lookup_roundtrip(
    sign: Sign,
    data_type: DataType,
    evals: Vec<<Backend as SnarkBackend>::F>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();

    let mle = MLE::from_evaluations_vec(LOG_SIZE, evals);
    let tracked_poly = prover.track_and_commit_mat_mv_poly(&mle).unwrap();
    let tracked_poly_id = tracked_poly.id();

    let schema = Schema::new(vec![Field::new("input", data_type, false)]);
    let field_ref = schema.fields()[0].clone();
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(field_ref.clone(), tracked_poly);
    let tracked_table = TrackedTable::new(Some(schema.clone()), tracked_polys, LOG_SIZE);

    let sign_node = Arc::new(SignNode::<Backend>::new(sign));
    let root = Arc::new(Node::Gadget(sign_node.clone()));
    let tree = Tree::new_from_root(root.clone());

    let gadget_payload = IndexMap::from([(INPUT_LABEL.to_string(), tracked_table)]);
    let mut prover_payloads = IndexMap::new();
    prover_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let mut gadget_ir = ProverGadgetReadyIr::new(tree.clone(), prover_payloads);

    sign_node.prove(&mut prover, &mut gadget_ir, root.id())?;

    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let tracked_oracle = verifier.track_mv_com_by_id(tracked_poly_id).unwrap();
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(field_ref, tracked_oracle);
    let table_oracle = TrackedTableOracle::new(Some(schema), tracked_oracles, LOG_SIZE);

    let gadget_payload = IndexMap::from([(INPUT_LABEL.to_string(), table_oracle)]);
    let mut verifier_payloads = IndexMap::new();
    verifier_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let mut verifier_ir = VerifierGadgetReadyIr::new(tree, verifier_payloads);

    sign_node.verify(&mut verifier, &mut verifier_ir, root.id())?;
    verifier.verify()?;
    Ok(())
}

#[test]
fn completeness_sign_non_negative_lookup_roundtrip() {
    let evals = vec![
        <Backend as SnarkBackend>::F::from(0u64),
        <Backend as SnarkBackend>::F::from(1u64),
        <Backend as SnarkBackend>::F::from(2u64),
        <Backend as SnarkBackend>::F::from(3u64),
    ];
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::UInt8, evals).unwrap();
}

#[test]
fn completeness_sign_non_positive_lookup_roundtrip() {
    let evals = vec![
        <Backend as SnarkBackend>::F::from(0u64),
        -<Backend as SnarkBackend>::F::from(1u64),
        -<Backend as SnarkBackend>::F::from(2u64),
        <Backend as SnarkBackend>::F::from(0u64),
    ];
    run_sign_lookup_roundtrip(Sign::NonPositive, DataType::Int8, evals).unwrap();
}

#[test]
fn completeness_sign_positive_lookup_roundtrip() {
    let evals = vec![
        <Backend as SnarkBackend>::F::from(1u64),
        <Backend as SnarkBackend>::F::from(2u64),
        <Backend as SnarkBackend>::F::from(3u64),
        <Backend as SnarkBackend>::F::from(4u64),
    ];
    run_sign_lookup_roundtrip(Sign::Positive, DataType::UInt8, evals).unwrap();
}

#[test]
fn completeness_sign_negative_lookup_roundtrip() {
    let evals = vec![
        -<Backend as SnarkBackend>::F::from(1u64),
        -<Backend as SnarkBackend>::F::from(2u64),
        -<Backend as SnarkBackend>::F::from(3u64),
        -<Backend as SnarkBackend>::F::from(4u64),
    ];
    run_sign_lookup_roundtrip(Sign::Negative, DataType::Int8, evals).unwrap();
}

#[test]
fn soundness_sign_positive_rejects_zero() {
    let evals = vec![
        <Backend as SnarkBackend>::F::from(1u64),
        <Backend as SnarkBackend>::F::from(0u64),
        <Backend as SnarkBackend>::F::from(2u64),
        <Backend as SnarkBackend>::F::from(3u64),
    ];
    let err = run_sign_lookup_roundtrip(Sign::Positive, DataType::UInt8, evals).unwrap_err();
    assert_soundness_error(err);
}
#[test]
fn soundness_sign_non_negative_rejects_negative() {
    let evals = vec![
        -<Backend as SnarkBackend>::F::from(1u64),
        <Backend as SnarkBackend>::F::from(0u64),
        <Backend as SnarkBackend>::F::from(2u64),
        <Backend as SnarkBackend>::F::from(3u64),
    ];
    let err = run_sign_lookup_roundtrip(Sign::NonNegative, DataType::Int8, evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn soundness_sign_non_positive_rejects_positive() {
    let evals = vec![
        -<Backend as SnarkBackend>::F::from(1u64),
        <Backend as SnarkBackend>::F::from(0u64),
        <Backend as SnarkBackend>::F::from(2u64),
        -<Backend as SnarkBackend>::F::from(3u64),
    ];
    let err = run_sign_lookup_roundtrip(Sign::NonPositive, DataType::Int8, evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn soundness_sign_negative_rejects_zero() {
    let evals = vec![
        -<Backend as SnarkBackend>::F::from(1u64),
        -<Backend as SnarkBackend>::F::from(2u64),
        <Backend as SnarkBackend>::F::from(0u64),
        -<Backend as SnarkBackend>::F::from(3u64),
    ];
    let err = run_sign_lookup_roundtrip(Sign::Negative, DataType::Int8, evals).unwrap_err();
    assert_soundness_error(err);
}
