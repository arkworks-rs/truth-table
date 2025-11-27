use ark_piop::SnarkBackend;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::id::NodeId,
        tree::{Node, Payload},
    },
    prover::payloads::{DataFramePayload, MemTablePayload},
};

pub struct ExecutionPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> LocalPass<B, DataFramePayload, MemTablePayload> for ExecutionPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &dyn Node<B>,
        id: NodeId,
        payload: &DataFramePayload,
    ) -> MemTablePayload {
        todo!()
    }
}
