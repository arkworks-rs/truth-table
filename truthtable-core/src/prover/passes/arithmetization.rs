use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::{
    irs::{ir::LocalPass, nodes::id::NodeId, tree::Node},
    prover::payloads::{ArithPayload, DataFramePayload, MemTablePayload},
};

pub struct ExecutionPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(F, MvPCS, UvPCS)>,
}

impl<B> LocalPass<F, MvPCS, UvPCS, MemTablePayload, ArithPayload<F>>
    for ExecutionPass<B>
where
B:SnarkBackend
{
    fn transform(
        &self,
        node: &dyn Node<B>,
        id: NodeId,
        payload: &MemTablePayload,
    ) -> ArithPayload<F> {
        todo!()
    }
}
