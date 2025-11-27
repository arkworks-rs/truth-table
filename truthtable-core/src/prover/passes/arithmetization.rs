use ark_ff::PrimeField;
use ark_piop::SnarkBackend;

use crate::{
    irs::{ir::LocalPass, nodes::id::NodeId, tree::Node},
    prover::payloads::{ArithPayload, MemTablePayload},
};

pub struct ExecutionPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> LocalPass<B, MemTablePayload, ArithPayload<B::F>> for ExecutionPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &dyn Node<B>,
        id: NodeId,
        payload: &MemTablePayload,
    ) -> ArithPayload<B::F> {
        todo!()
    }
}
