use ark_piop::SnarkBackend;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{ArithPayload, TrackedPayload},
};
use arithmetic::table::TrackedTable;
use indexmap::IndexMap;

pub struct TrackingPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B: SnarkBackend> TrackingPass<B> {
    pub fn new() -> Self {
        Self {
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
    ) -> TrackedPayload<B> {
        match payload {
            ArithPayload::PlanPayload(arith_table) => {
                TrackedPayload::PlanPayload(arith_to_tracked(arith_table))
            }
            ArithPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (k, arith_table) in map {
                    out.insert(k.clone(), arith_to_tracked(arith_table));
                }
                TrackedPayload::GadgetPayload(out)
            }
        }
    }
}

fn arith_to_tracked<B: SnarkBackend>(
    arith_table: &arithmetic::table::ArithTable<B::F>,
) -> TrackedTable<B> {
    // Without commitments, just mirror schema/log_size and leave polynomials empty.
    TrackedTable::new(
        arith_table.schema(),
        IndexMap::new(),
        arith_table.log_size(),
    )
}
