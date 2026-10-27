use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, pcs::PCS,
    test_utils::prelude_with_vars, types::CommitmentBinding,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_expr::logical_plan::builder::table_scan;
use indexmap::IndexMap;

use super::LpNode;
use crate::irs::{
    ir::Ir,
    nodes::{ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
    tree::Tree,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const NV: usize = 2;

fn scan_tree() -> Tree<B> {
    let schema = Schema::new(vec![
        Field::new("c", DataType::Utf8, false),
        Field::new("d", DataType::Utf8, false),
    ]);
    let plan = table_scan(Some("t"), &schema, None)
        .unwrap()
        .build()
        .unwrap();
    Tree::from_logical_plan(&plan)
}

fn names<'a>(fields: impl Iterator<Item = &'a FieldRef>) -> Vec<String> {
    fields.map(|field| field.name().clone()).collect()
}

/// The scan's payload in the encoder's order, with `c` ranked and `d` not.
fn flat_fields() -> Vec<FieldRef> {
    ["c", "c__length", "c__rank", "d", "d__length"]
        .into_iter()
        .map(|name| Arc::new(Field::new(name, DataType::Utf8, false)))
        .chain([ACTIVATOR_FIELD.clone()])
        .collect()
}

/// Both sides take the rank out of the scan's payload, keep every other
/// segment in order, and cache the rank's id, which is the same on both.
#[test]
fn a_scan_sets_its_ranks_aside_on_both_sides() {
    let (mut prover, mut verifier) = prelude_with_vars::<B>(NV).unwrap();
    let fields = flat_fields();
    let schema = Schema::new(
        fields
            .iter()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    );

    // Tracked as a scan tracks the owner's commitments.
    let mut polys = IndexMap::new();
    let mut commitments = Vec::new();
    for (i, field) in fields.iter().enumerate() {
        let evals: Vec<F> = (0..1u64 << NV)
            .map(|row| F::from(10 * i as u64 + row))
            .collect();
        let mle = MLE::from_evaluations_vec(NV, evals);
        let commitment = <B as SnarkBackend>::MvPCS::commit(
            prover.mv_pcs_prover_param(),
            &Arc::new(mle.clone()),
        )
        .unwrap();
        let poly = prover
            .track_mat_mv_poly_with_commitment(&mle, commitment, CommitmentBinding::External)
            .unwrap();
        polys.insert(field.clone(), poly);
        commitments.push(commitment);
    }
    let rank_id = polys[2].id();
    let kept = [
        "c",
        "c__length",
        "d",
        "d__length",
        arithmetic::ACTIVATOR_COL_NAME,
    ];

    let tree = scan_tree();
    let id = tree.root().id();
    let scan = LpNode::of(tree.root()).expect("the root is a table scan");
    let table = TrackedTable::new(Some(schema.clone()), polys, NV);
    let mut ir: crate::prover::irs::VirtualizedIr<B> = Ir::new(
        tree.clone(),
        [(id, Some(PayloadStructure::PlanPayload(table)))].into(),
    );
    ProverNodeOps::add_virtual_witness(scan, id, &mut ir).unwrap();
    let Some(PayloadStructure::PlanPayload(stripped)) = ir.payload_for_node(&id) else {
        panic!("the scan keeps a plan payload");
    };
    assert_eq!(names(stripped.tracked_polys().keys()), kept);
    assert_eq!(names(stripped.schema_ref().unwrap().fields().iter()), kept);
    assert!(stripped.side_cols().is_empty());
    assert_eq!(scan.rank_poly("c"), Some((rank_id, NV)));
    assert_eq!(scan.rank_poly("d"), None);

    verifier.set_proof(prover.build_proof().unwrap());
    let oracles: IndexMap<_, _> = fields
        .iter()
        .zip(commitments)
        .map(|(field, commitment)| {
            let oracle = verifier
                .track_mat_mv_com_with_binding(commitment, CommitmentBinding::External)
                .unwrap();
            (field.clone(), oracle)
        })
        .collect();
    let tree = scan_tree();
    let id = tree.root().id();
    let scan = LpNode::of(tree.root()).expect("the root is a table scan");
    let table = TrackedTableOracle::new(Some(schema), oracles, NV);
    let mut ir: crate::verifier::irs::VirtualizedIr<B> = Ir::new(
        tree.clone(),
        [(id, Some(PayloadStructure::PlanPayload(table)))].into(),
    );
    VerifierNodeOps::add_virtual_witness(scan, id, &mut ir).unwrap();
    let Some(PayloadStructure::PlanPayload(stripped)) = ir.payload_for_node(&id) else {
        panic!("the scan keeps a plan payload");
    };
    assert_eq!(names(stripped.tracked_oracles().keys()), kept);
    assert_eq!(names(stripped.schema_ref().unwrap().fields().iter()), kept);
    assert_eq!(scan.rank_poly("c"), Some((rank_id, NV)));
    assert_eq!(scan.rank_poly("d"), None);
}

/// A scan without a payload, or without ranks, leaves its payload as it is
/// and caches nothing.
#[test]
fn a_scan_without_ranks_is_left_alone() {
    let tree = scan_tree();
    let id = tree.root().id();
    let scan = LpNode::of(tree.root()).expect("the root is a table scan");
    let mut ir: crate::prover::irs::VirtualizedIr<B> = Ir::new(tree.clone(), [(id, None)].into());
    ProverNodeOps::add_virtual_witness(scan, id, &mut ir).unwrap();
    assert!(ir.payload_for_node(&id).is_none());
    assert_eq!(scan.rank_poly("c"), None);
}
