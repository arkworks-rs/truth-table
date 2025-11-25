use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use ark_std::cfg_iter;
use indexmap::IndexMap;

use crate::irs::{
    nodes::id::NodeId,
    tree::{Node, Payload, Tree},
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
pub struct Ir<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
    Pd: Payload,
> {
    tree: Tree<F, MvPCS, UvPCS>,
    payloads: IndexMap<NodeId, Pd>,
}

impl<
    Pd: Payload,
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> Ir<F, MvPCS, UvPCS, Pd>
{
    pub fn new(tree: Tree<F, MvPCS, UvPCS>, payloads: IndexMap<NodeId, Pd>) -> Self {
        Self { tree, payloads }
    }

    pub fn tree(&self) -> &Tree<F, MvPCS, UvPCS> {
        &self.tree
    }

    pub fn payloads(&self) -> &IndexMap<NodeId, Pd> {
        &self.payloads
    }

    pub fn payload_for_node(&self, node_id: &NodeId) -> Option<&Pd> {
        self.payloads.get(node_id)
    }
}
impl<F, MvPCS, UvPCS, PIn> Ir<F, MvPCS, UvPCS, PIn>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
    PIn: Payload,
{
    pub fn apply_local_pass_sequential<POut, P>(&self, pass: &P) -> Ir<F, MvPCS, UvPCS, POut>
    where
        POut: Payload,
        P: LocalPass<F, MvPCS, UvPCS, PIn, POut>,
    {
        let mut out = IndexMap::with_capacity(self.tree.arena().len());
        for (id, node) in self.tree.arena().iter() {
            let p_in = &self.payloads[id];
            let p_out = pass.transform(node.as_ref(), id.clone(), p_in);
            out.insert(id.clone(), p_out);
        }
        Ir {
            tree: self.tree.clone(),
            payloads: out,
        }
    }

    pub fn apply_local_pass_parallel<POut, P>(&self, pass: &P) -> Ir<F, MvPCS, UvPCS, POut>
    where
        PIn: Payload + Send + Sync,
        POut: Payload + Send + Sync,
        P: LocalPass<F, MvPCS, UvPCS, PIn, POut> + Sync,
    {
        use rayon::prelude::*;
        let out_vec: Vec<(NodeId, POut)> = self
            .tree
            .arena()
            .into_par_iter()
            .map(|(id, node)| {
                let p_in = &self.payloads[id];
                let p_out = pass.transform(node.as_ref(), id.clone(), p_in);
                (id.clone(), p_out)
            })
            .collect();
        let out: IndexMap<NodeId, POut> = out_vec.into_iter().collect();
        Ir {
            tree: self.tree.clone(),
            payloads: out,
        }
    }
}
pub trait LocalPass<F, MvPCS, UvPCS, PIn, POut>: Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
    PIn: Payload,
    POut: Payload,
{
    fn transform(&self, node: &dyn Node<F, MvPCS, UvPCS>, id: NodeId, payload: &PIn) -> POut;
}
