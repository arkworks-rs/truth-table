use ark_piop::SnarkBackend;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{ArithPayload, TrackedPayload},
};

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
        todo!()
    }
}
