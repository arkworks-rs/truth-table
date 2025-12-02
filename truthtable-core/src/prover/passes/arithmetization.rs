use ark_ff::PrimeField;
use ark_piop::SnarkBackend;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{ArithPayload, MaterializedPayload},
};

pub struct ArithmetizationPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> ArithmetizationPass<B> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B> LocalPass<B, MaterializedPayload, ArithPayload<B::F>> for ArithmetizationPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: &MaterializedPayload,
    ) -> ArithPayload<B::F> {
        todo!()
    }
}
