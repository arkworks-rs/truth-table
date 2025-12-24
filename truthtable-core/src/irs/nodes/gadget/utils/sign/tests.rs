use std::sync::Arc;

use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::arithmetic::mat_poly::mle::MLE;
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

#[test]
fn sign_non_negative_lookup_roundtrip() {
    type Backend = DefaultSnarkBackend;

    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();

    let log_size = 2;
    let evals = vec![
        <Backend as SnarkBackend>::F::from(0u64),
        <Backend as SnarkBackend>::F::from(1u64),
        <Backend as SnarkBackend>::F::from(2u64),
        <Backend as SnarkBackend>::F::from(3u64),
    ];
    let mle = MLE::from_evaluations_vec(log_size, evals);
    let tracked_poly = prover.track_and_commit_mat_mv_poly(&mle).unwrap();
    let tracked_poly_id = tracked_poly.id();

    let schema = Schema::new(vec![Field::new("input", DataType::UInt8, false)]);
    let field_ref = schema.fields()[0].clone();
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(field_ref.clone(), tracked_poly);
    let tracked_table = TrackedTable::new(Some(schema.clone()), tracked_polys, log_size);

    let sign_node = Arc::new(SignNode::<Backend>::new(Sign::NonNegative));
    let root = Arc::new(Node::Gadget(sign_node.clone()));
    let tree = Tree::new_from_root(root.clone());

    let gadget_payload = IndexMap::from([(INPUT_LABEL.to_string(), tracked_table)]);
    let mut prover_payloads = IndexMap::new();
    prover_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let mut gadget_ir = ProverGadgetReadyIr::new(tree.clone(), prover_payloads);

    sign_node
        .prove(&mut prover, &mut gadget_ir, root.id())
        .unwrap();

    let proof = prover.build_proof().unwrap();
    verifier.set_proof(proof);

    let tracked_oracle = verifier.track_mv_com_by_id(tracked_poly_id).unwrap();
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(field_ref, tracked_oracle);
    let table_oracle = TrackedTableOracle::new(Some(schema), tracked_oracles, log_size);

    let gadget_payload = IndexMap::from([(INPUT_LABEL.to_string(), table_oracle)]);
    let mut verifier_payloads = IndexMap::new();
    verifier_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let mut verifier_ir = VerifierGadgetReadyIr::new(tree, verifier_payloads);

    sign_node
        .verify(&mut verifier, &mut verifier_ir, root.id())
        .unwrap();
    verifier.verify().unwrap();
}
