use ark_piop::{SnarkBackend, prover::ArgProver};

use crate::{
    ctx_oracles::CtxOracles, irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    }, prover::payloads::{ArithPayload, TrackedPayload}
};
use arithmetic::table::TrackedTable;
use indexmap::IndexMap;
use std::cell::{Cell, RefCell};
use tracing::{debug, info};

/// A tracking pass that tracks and commits the prover's arithmetized tables
///
/// This pass converts an IR with arithmetized tables into an IR with tracked tables; i.e. tables that are commited and added to the transcript, therefore tracked by the SNARK prover with an associated id. Note that this pass is stateful, as it requires access to the prover instance to perform the tracking and committing.
pub struct TrackingPass<B: SnarkBackend> {
    prover: RefCell<ArgProver<B>>,
    total_committed: Cell<usize>, // Track committed polynomial count across the entire pass.
    ctx_oracles: CtxOracles<B>,
}

impl<B: SnarkBackend> TrackingPass<B> {
    pub fn new(prover: ArgProver<B>, ctx_oracles: CtxOracles<B>) -> Self {
        Self {
            prover: RefCell::new(prover),
            total_committed: Cell::new(0),
            ctx_oracles,
        }
    }
}

impl<B: SnarkBackend> Drop for TrackingPass<B> {
    fn drop(&mut self) {
        info!(
            committed = self.total_committed.get(),
            "total committed polynomials after tracking pass"
        );
    }
}

impl<B> LocalPass<B, ArithPayload<B::F>, TrackedPayload<B>> for TrackingPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }
    fn transform(
        &self,
        _node: &Node<B>,
        _id: NodeId,
        payload: Option<&ArithPayload<B::F>>,
    ) -> Option<TrackedPayload<B>> {
        match payload? {
            ArithPayload::PlanPayload(arith_table) => Some(TrackedPayload::PlanPayload(
                arith_to_tracked(arith_table, &self.prover, &self.total_committed),
            )),
            ArithPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (k, arith_table) in map {
                    out.insert(
                        k.clone(),
                        arith_to_tracked(arith_table, &self.prover, &self.total_committed),
                    );
                }

                if out.is_empty() {
                    None
                } else {
                    Some(TrackedPayload::GadgetPayload(out))
                }
            }
        }
    }
}
fn arith_to_tracked<B: SnarkBackend>(
    arith_table: &arithmetic::table::ArithTable<B::F>,
    prover: &RefCell<ArgProver<B>>,
    total_committed: &Cell<usize>,
) -> TrackedTable<B> {
    debug!(
        poly_count = arith_table.polynomials().len(),
        log_size = arith_table.log_size(),
        "tracking arithmetized polynomials"
    );
    let mut tracked_polys = IndexMap::with_capacity(arith_table.polynomials().len());
    for (field_ref, mle_arc) in arith_table.polynomials() {
        debug!(field = ?field_ref, "tracking polynomial");
        let tracked_poly = prover
            .borrow_mut()
            .track_and_commit_mat_mv_poly(mle_arc)
            .expect("failed to track and commit polynomial");
        tracked_polys.insert(field_ref.clone(), tracked_poly);
        total_committed.set(total_committed.get() + 1);
    }

    TrackedTable::new(arith_table.schema(), tracked_polys, arith_table.log_size())
}
