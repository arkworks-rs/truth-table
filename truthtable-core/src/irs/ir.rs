use ark_piop::SnarkBackend;
use indexmap::IndexMap;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::irs::{
    nodes::{Node, NodeId},
    tree::{Payload, Tree},
};
pub struct Ir<B: SnarkBackend, Pd: Payload> {
    tree: Tree<B>,
    payloads: IndexMap<NodeId, Pd>,
}

impl<Pd: Payload, B: SnarkBackend> Ir<B, Pd> {
    pub fn new(tree: Tree<B>, payloads: IndexMap<NodeId, Pd>) -> Self {
        Self { tree, payloads }
    }

    pub fn tree(&self) -> &Tree<B> {
        &self.tree
    }

    pub fn payloads(&self) -> &IndexMap<NodeId, Pd> {
        &self.payloads
    }

    pub fn payload_for_node(&self, node_id: &NodeId) -> Option<&Pd> {
        self.payloads.get(node_id)
    }

    /// Render the IR as a Graphviz DOT string.
    ///
    /// When `show_payload` is `true`, each node label includes the debug
    /// representation of its payload below the node name. Otherwise, only the
    /// node name is shown.
    pub fn display_graphviz(&self, show_payload: bool) -> String {
        todo!()
    }
}
impl<B, PIn> Ir<B, PIn>
where
    B: SnarkBackend,
    PIn: Payload,
{
    pub fn apply_local_pass_sequential<POut, P>(&self, pass: &P) -> Ir<B, POut>
    where
        POut: Payload,
        P: LocalPass<B, PIn, POut>,
    {
        let mut out = IndexMap::with_capacity(self.tree.arena().len());
        for (id, node) in self.tree.arena().iter() {
            let p_in = &self.payloads[id];
            let p_out = pass.transform(node, id.clone(), p_in);
            out.insert(id.clone(), p_out);
        }
        Ir {
            tree: self.tree.clone(),
            payloads: out,
        }
    }

    pub fn apply_local_pass_parallel<POut, P>(&self, pass: &P) -> Ir<B, POut>
    where
        PIn: Payload + Send + Sync,
        POut: Payload + Send + Sync,
        P: LocalPass<B, PIn, POut> + Sync,
    {
        use rayon::prelude::*;
        let out_vec: Vec<(NodeId, POut)> = self
            .tree
            .arena()
            .into_par_iter()
            .map(|(id, node)| {
                let p_in = &self.payloads[id];
                let p_out = pass.transform(node, id.clone(), p_in);
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
pub trait LocalPass<B, PIn, POut>: Sync
where
    B: SnarkBackend,
    PIn: Payload,
    POut: Payload,
{
    fn transform(&self, node: &Node<B>, id: NodeId, payload: &PIn) -> POut;
}
