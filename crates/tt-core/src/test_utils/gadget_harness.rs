//! A minimal harness for unit-testing individual gadget nodes without
//! standing up the full IR pipeline.
//!
//! Typical usage: build a single-gadget `GadgetHarness`, populate its
//! payload slots by supplying `TableSpec`s, then hand it to
//! [`run_gadget_pipeline`] which runs prove → build_proof → set_proof →
//! verify end-to-end and returns the verification result.
//!
//! Payload columns are committed at harness-build time on the prover side;
//! the verifier tables are materialized after `set_proof` because
//! `track_mv_com_by_id` needs the proof in place first. The harness does
//! not model IR traversal or gadget-plan initialization — it is intended
//! for testing a single gadget in isolation.

use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkError,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    test_utils::prelude_with_vars,
    types::TrackerID,
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use datafusion::arrow::datatypes::{FieldRef, Schema};
use indexmap::IndexMap;

use crate::irs::{
    ir::Ir,
    nodes::{IsGadgetNode, Node, NodeId},
    payloads::PayloadStructure,
    tree::Tree,
};
use crate::prover::irs::GadgetReadyIr as ProverGadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

/// Description of one payload table to be built and committed.
pub struct TableSpec<F> {
    pub schema: Schema,
    pub log_size: usize,
    /// Data columns in insertion order (field, evaluations).
    pub cols: Vec<(FieldRef, Vec<F>)>,
    /// Optional activator column (evaluations). If `None`, the table has
    /// no activator.
    pub activator: Option<Vec<F>>,
}

/// A committed table plus the TrackerIDs the verifier needs to
/// reconstruct its mirror after `set_proof`.
struct CommittedTable<B: SnarkBackend> {
    prover: TrackedTable<B>,
    /// (field, tracker id) in insertion order (data cols first, then
    /// activator if present).
    field_ids: Vec<(FieldRef, TrackerID)>,
    schema: Schema,
    log_size: usize,
}

/// One-gadget IR primed for prove + verify.
pub struct GadgetHarness<B: SnarkBackend> {
    pub prover: ArgProver<B>,
    pub verifier: ArgVerifier<B>,
    pub gadget: Arc<dyn IsGadgetNode<B>>,
    pub node_id: NodeId,
    pub prover_ir: ProverGadgetReadyIr<B>,
    pub verifier_ir: VerifierGadgetReadyIr<B>,
    /// Per (target NodeId, label) -> committed table (kept so the pipeline
    /// can build the verifier tables after `set_proof`).
    committed: IndexMap<NodeId, IndexMap<String, CommittedTable<B>>>,
}

impl<B: SnarkBackend> GadgetHarness<B> {
    pub fn builder(srs_nv: usize) -> GadgetHarnessBuilder<B> {
        GadgetHarnessBuilder::new(srs_nv)
    }
}

/// Fluent builder for a `GadgetHarness`.
pub struct GadgetHarnessBuilder<B: SnarkBackend> {
    srs_nv: usize,
    gadget: Option<Arc<Node<B>>>,
    payloads: IndexMap<NodeId, IndexMap<String, TableSpec<B::F>>>,
}

impl<B: SnarkBackend> GadgetHarnessBuilder<B> {
    pub fn new(srs_nv: usize) -> Self {
        Self {
            srs_nv,
            gadget: None,
            payloads: IndexMap::new(),
        }
    }

    /// Register the gadget node under test. Must be called exactly once.
    pub fn with_gadget(mut self, gadget: Arc<Node<B>>) -> Self {
        assert!(
            matches!(gadget.as_ref(), Node::Gadget(_)),
            "GadgetHarness requires a Node::Gadget"
        );
        self.gadget = Some(gadget);
        self
    }

    /// Add a payload table for `node_id` under `label`. Multiple calls
    /// with the same `node_id` accumulate; a repeated `label` replaces.
    pub fn with_table(
        mut self,
        node_id: NodeId,
        label: &str,
        spec: TableSpec<B::F>,
    ) -> Self {
        self.payloads
            .entry(node_id)
            .or_default()
            .insert(label.to_string(), spec);
        self
    }

    /// Commit all payload columns on the prover side, populate the prover
    /// IR's payload map, and remember the TrackerIDs so the pipeline can
    /// materialize the verifier tables after `set_proof`. The verifier IR
    /// starts with empty payloads.
    pub fn build(self) -> GadgetHarness<B> {
        let (mut prover, verifier) =
            prelude_with_vars::<B>(self.srs_nv).expect("SRS setup should succeed");

        let gadget_node = self.gadget.expect("must call with_gadget()");
        let node_id = gadget_node.id();
        let gadget_impl = match gadget_node.as_ref() {
            Node::Gadget(g) => g.clone(),
            _ => unreachable!("verified by with_gadget"),
        };

        let tree = Tree::<B>::new_from_root(gadget_node);
        let mut prover_ir: ProverGadgetReadyIr<B> = Ir::new_empty(tree.clone());
        let verifier_ir: VerifierGadgetReadyIr<B> = Ir::new_empty(tree);

        let mut committed: IndexMap<NodeId, IndexMap<String, CommittedTable<B>>> =
            IndexMap::new();

        for (target_id, label_map) in self.payloads {
            let mut prover_payload: IndexMap<String, TrackedTable<B>> = IndexMap::new();
            let mut committed_map: IndexMap<String, CommittedTable<B>> = IndexMap::new();

            for (label, spec) in label_map {
                let table = commit_prover_table(&mut prover, &spec);
                prover_payload.insert(label.clone(), table.prover.clone());
                committed_map.insert(label, table);
            }

            prover_ir.set_payload_for_node(
                target_id,
                Some(PayloadStructure::GadgetPayload(prover_payload)),
            );
            committed.insert(target_id, committed_map);
        }

        GadgetHarness {
            prover,
            verifier,
            gadget: gadget_impl,
            node_id,
            prover_ir,
            verifier_ir,
            committed,
        }
    }
}

fn commit_prover_table<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    spec: &TableSpec<B::F>,
) -> CommittedTable<B> {
    let mut polys: IndexMap<FieldRef, TrackedPoly<B>> = IndexMap::new();
    let mut field_ids: Vec<(FieldRef, TrackerID)> = Vec::new();

    for (field, evals) in &spec.cols {
        let poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                spec.log_size,
                evals.clone(),
            ))
            .expect("commit data col");
        field_ids.push((field.clone(), poly.id()));
        polys.insert(field.clone(), poly);
    }

    if let Some(activator_evals) = &spec.activator {
        let activator_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                spec.log_size,
                activator_evals.clone(),
            ))
            .expect("commit activator");
        field_ids.push((ACTIVATOR_FIELD.clone(), activator_poly.id()));
        polys.insert(ACTIVATOR_FIELD.clone(), activator_poly);
    }

    let prover_table = TrackedTable::<B>::new(Some(spec.schema.clone()), polys, spec.log_size);
    CommittedTable {
        prover: prover_table,
        field_ids,
        schema: spec.schema.clone(),
        log_size: spec.log_size,
    }
}

fn materialize_verifier_table<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    committed: &CommittedTable<B>,
) -> Result<TrackedTableOracle<B>, SnarkError> {
    let mut oracles: IndexMap<FieldRef, TrackedOracle<B>> = IndexMap::new();
    for (field, id) in &committed.field_ids {
        let oracle = verifier.track_mv_com_by_id(*id)?;
        oracles.insert(field.clone(), oracle);
    }
    Ok(TrackedTableOracle::<B>::new(
        Some(committed.schema.clone()),
        oracles,
        committed.log_size,
    ))
}

/// Runs prove → build_proof → set_proof → verify on a fully-populated
/// harness and returns the verifier's `verify()` result. Errors at any
/// stage bubble up.
pub fn run_gadget_pipeline<B: SnarkBackend>(
    mut harness: GadgetHarness<B>,
) -> Result<(), SnarkError> {
    // 1. Prover: run the gadget's prove and compile the proof.
    harness
        .gadget
        .prove(&mut harness.prover, &mut harness.prover_ir, harness.node_id)?;
    let proof = harness.prover.build_proof()?;

    // 2. Verifier: register the proof, then materialize the verifier
    //    tables (needs proof to be present so track_mv_com_by_id works).
    harness.verifier.set_proof(proof);
    for (target_id, committed_map) in &harness.committed {
        let mut verifier_payload: IndexMap<String, TrackedTableOracle<B>> =
            IndexMap::new();
        for (label, committed_table) in committed_map {
            let oracle_table =
                materialize_verifier_table(&mut harness.verifier, committed_table)?;
            verifier_payload.insert(label.clone(), oracle_table);
        }
        harness.verifier_ir.set_payload_for_node(
            *target_id,
            Some(PayloadStructure::GadgetPayload(verifier_payload)),
        );
    }

    // 3. Verifier: run the gadget's verify + finalize.
    harness.gadget.verify(
        &mut harness.verifier,
        &mut harness.verifier_ir,
        harness.node_id,
    )?;
    harness.verifier.verify()?;
    Ok(())
}
