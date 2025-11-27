use ark_piop::SnarkBackend;

use crate::{
    irs::{ir::LocalPass, nodes::id::NodeId, tree::Node},
    prover::payloads::{ArithPayload, TrackedPayload},
};

pub struct ExecutionPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> LocalPass<B, ArithPayload<B::F>, TrackedPayload<B>> for ExecutionPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &dyn Node<B>,
        id: NodeId,
        payload: &ArithPayload<B::F>,
    ) -> TrackedPayload<B> {
        todo!()
    }
}
