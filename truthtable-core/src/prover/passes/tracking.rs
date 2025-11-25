use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::{
    irs::{ir::LocalPass, nodes::id::NodeId, tree::Node},
    prover::payloads::{ArithPayload, TrackedPayload},
};

pub struct ExecutionPass<F, MvPCS, UvPCS> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> LocalPass<F, MvPCS, UvPCS, ArithPayload<F>, TrackedPayload<F, MvPCS, UvPCS>>
    for ExecutionPass<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn transform(
        &self,
        node: &dyn Node<F, MvPCS, UvPCS>,
        id: NodeId,
        payload: &ArithPayload<F>,
    ) -> TrackedPayload<F, MvPCS, UvPCS> {
        todo!()
    }
}
