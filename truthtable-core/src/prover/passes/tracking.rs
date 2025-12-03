use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::{SnarkBackend, prover::ArgProver};

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{ArithPayload, TrackedPayload},
};
use arithmetic::table::TrackedTable;
use indexmap::IndexMap;
use std::cell::RefCell;

pub struct TrackingPass<B: SnarkBackend> {
    // pub ctx: ExecCtx,
    prover: RefCell<ArgProver<B>>,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B: SnarkBackend> TrackingPass<B> {
    pub fn new(prover: ArgProver<B>) -> Self {
        Self {
            prover: RefCell::new(prover),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B> LocalPass<B, ArithPayload<B::F>, TrackedPayload<B>> for TrackingPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: &ArithPayload<B::F>,
    ) -> Option<TrackedPayload<B>> {
        match payload {
            ArithPayload::PlanPayload(arith_table) => {
                Some(TrackedPayload::PlanPayload(arith_to_tracked(
                    arith_table,
                    &self.prover,
                )))
            }
            ArithPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (k, arith_table) in map {
                    out.insert(k.clone(), arith_to_tracked(arith_table, &self.prover));
                }
                Some(TrackedPayload::GadgetPayload(out))
            }
        }
    }
}

fn arith_to_tracked<B: SnarkBackend>(
    arith_table: &arithmetic::table::ArithTable<B::F>,
    prover: &RefCell<ArgProver<B>>,
) -> TrackedTable<B> {
    let mut tracked_polys = IndexMap::with_capacity(arith_table.polynomials().len());
    for (field_ref, mle_arc) in arith_table.polynomials() {
        let tracked_poly = prover
            .borrow_mut()
            .track_and_commit_mat_mv_poly(mle_arc)
            .expect("failed to track and commit polynomial");
        tracked_polys.insert(field_ref.clone(), tracked_poly);
    }

    TrackedTable::new(arith_table.schema(), tracked_polys, arith_table.log_size())
}
