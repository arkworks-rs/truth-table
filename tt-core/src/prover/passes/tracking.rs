use ark_piop::{SnarkBackend, prover::ArgProver};
use datafusion::arrow::datatypes::{Field, Schema};

use crate::irs::nodes::IsNode;
use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{ArithPayload, CommittedPayload, TrackedPayload},
};
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::ArithTableOracle;
use indexmap::IndexMap;
use std::cell::{Cell, RefCell};
use tracing::{debug, info};
/// A tracking pass that tracks the prover's arithmetized tables using commitments.
///
/// This pass converts an IR with committed table oracles into an IR with tracked tables; i.e.
/// tables that are tracked by the SNARK prover with an associated id. Commitments are supplied
/// by the commitment pass, so this pass stays sequential and only tracks.
pub struct TrackingPass<'a, B: SnarkBackend> {
    prover: RefCell<ArgProver<B>>,
    total_committed: Cell<usize>, // Track committed polynomial count across the entire pass.
    arith_payloads: &'a IndexMap<NodeId, Option<ArithPayload<B::F>>>,
}

impl<'a, B: SnarkBackend> TrackingPass<'a, B> {
    pub fn new(
        prover: ArgProver<B>,
        arith_payloads: &'a IndexMap<NodeId, Option<ArithPayload<B::F>>>,
    ) -> Self {
        Self {
            prover: RefCell::new(prover),
            total_committed: Cell::new(0),
            arith_payloads,
        }
    }
}

impl<'a, B: SnarkBackend> Drop for TrackingPass<'a, B> {
    fn drop(&mut self) {
        info!(
            committed = self.total_committed.get(),
            "total tracked polynomials after tracking pass"
        );
    }
}

impl<'a, B> LocalPass<B, CommittedPayload<B>, TrackedPayload<B>> for TrackingPass<'a, B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }
    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: Option<&CommittedPayload<B>>,
    ) -> Option<TrackedPayload<B>> {
        let arith_payload = self.arith_payloads.get(&id).and_then(|p| p.as_ref())?;
        match (payload?, arith_payload) {
            (CommittedPayload::PlanPayload(oracle), ArithPayload::PlanPayload(arith_table)) => {
                if arith_table.polynomials().is_empty() {
                    return None;
                }
                Some(TrackedPayload::PlanPayload(
                    arith_to_tracked_with_commitment(
                        arith_table,
                        oracle,
                        &self.prover,
                        &self.total_committed,
                    ),
                ))
            }
            (
                CommittedPayload::GadgetPayload(commit_map),
                ArithPayload::GadgetPayload(arith_map),
            ) => {
                let mut out = IndexMap::new();
                for (key, oracle) in commit_map {
                    let arith_table = arith_map
                        .get(key)
                        .expect("commitment payload missing arith table entry");
                    if arith_table.polynomials().is_empty() {
                        continue;
                    }
                    out.insert(
                        key.clone(),
                        arith_to_tracked_with_commitment(
                            arith_table,
                            oracle,
                            &self.prover,
                            &self.total_committed,
                        ),
                    );
                }

                if out.is_empty() {
                    None
                } else {
                    Some(TrackedPayload::GadgetPayload(out))
                }
            }
            _ => {
                debug!(
                    node = node.name(),
                    "tracking pass payload mismatch for node"
                );
                None
            }
        }
    }

    fn name(&self) -> &'static str {
        "Prover Tracking"
    }
}

fn arith_to_tracked_with_commitment<B: SnarkBackend>(
    arith_table: &arithmetic::table::ArithTable<B::F>,
    oracle: &ArithTableOracle<B>,
    prover: &RefCell<ArgProver<B>>,
    total_committed: &Cell<usize>,
) -> TrackedTable<B> {
    debug!(
        poly_count = arith_table.polynomials().len(),
        log_size = arith_table.log_size(),
        "tracking arithmetized polynomials with commitments"
    );
    let mut tracked_polys = IndexMap::with_capacity(arith_table.polynomials().len());
    let mut prover = prover.borrow_mut();
    for (field_ref, mle_arc) in arith_table.polynomials() {
        let commitment = oracle
            .comitments()
            .get(field_ref)
            .expect("commitment oracle missing field")
            .clone();
        let tracked_poly = prover
            .track_mat_mv_poly_with_commitment(mle_arc, commitment)
            .expect("failed to track polynomial with commitment");
        tracked_polys.insert(field_ref.clone(), tracked_poly);
        total_committed.set(total_committed.get() + 1);
    }

    debug_assert_eq!(
        arith_table.log_size(),
        oracle.log_size(),
        "commitment oracle log_size should match arith table"
    );
    let schema = tracked_schema_with_oracle_metadata(
        arith_table.schema(),
        oracle.schema_ref(),
        tracked_polys.keys().map(|f| f.as_ref().clone()).collect(),
    );
    TrackedTable::new(schema, tracked_polys, arith_table.log_size())
}

fn tracked_schema_with_oracle_metadata(
    arith_schema: Option<Schema>,
    oracle_schema: Option<&Schema>,
    tracked_fields: Vec<Field>,
) -> Option<Schema> {
    if arith_schema.is_none() && oracle_schema.is_none() {
        return None;
    }

    // Keep field ordering exactly aligned with tracked_polys keys, while merging
    // table-level metadata from arith + oracle schemas (oracle takes precedence).
    let mut metadata = arith_schema
        .as_ref()
        .map(|s| s.metadata().clone())
        .unwrap_or_default();
    if let Some(schema) = oracle_schema {
        metadata.extend(schema.metadata().clone());
    }
    Some(Schema::new_with_metadata(tracked_fields, metadata))
}
