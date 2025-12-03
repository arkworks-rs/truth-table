use ark_piop::SnarkBackend;
use indexmap::IndexMap;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::irs::{
    nodes::{IsNode, Node, NodeId},
    tree::{Payload, Tree},
};
pub struct Ir<B: SnarkBackend, Pd: Payload> {
    tree: Tree<B>,
    payloads: IndexMap<NodeId, Option<Pd>>,
}

impl<Pd: Payload, B: SnarkBackend> Ir<B, Pd> {
    pub fn new(tree: Tree<B>, payloads: IndexMap<NodeId, Option<Pd>>) -> Self {
        Self { tree, payloads }
    }

    pub fn tree(&self) -> &Tree<B> {
        &self.tree
    }

    pub fn payloads(&self) -> &IndexMap<NodeId, Option<Pd>> {
        &self.payloads
    }

    pub fn payload_for_node(&self, node_id: &NodeId) -> Option<&Pd> {
        self.payloads.get(node_id).and_then(|opt| opt.as_ref())
    }

    /// Render the IR as a Graphviz DOT string.
    ///
    /// When `show_payload` is `true`, each node label includes the debug
    /// representation of its payload below the node name. Otherwise, only the
    /// node name is shown.
    pub fn display_graphviz(&self, show_payload: bool) -> String {
        fn escape_html(input: &str) -> String {
            input
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        }

        fn node_id<B: SnarkBackend>(node: &Node<B>) -> NodeId {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            node.hash(&mut hasher);
            hasher.finish()
        }

        let mut dot = String::from("digraph ir {\n  node [shape=box];\n");

        for (id, node) in self.tree.arena().iter() {
            let name = node.name();
            let (label, html) = if show_payload {
                if let Some(Some(payload)) = self.payloads.get(id) {
                    let payload_str =
                        escape_html(&format!("{}", payload)).replace('\n', "<BR ALIGN=\"LEFT\"/>");
                    if payload_str.is_empty() {
                        (escape_html(&name), false)
                    } else {
                        (
                            format!(
                                "<{}<BR/><FONT COLOR=\"blue\">{}</FONT>>",
                                escape_html(&name),
                                payload_str
                            ),
                            true,
                        )
                    }
                } else {
                    (escape_html(&name), false)
                }
            } else {
                (escape_html(&name), false)
            };
            if html {
                dot.push_str(&format!("  \"{}\" [label={}];\n", id, label));
            } else {
                dot.push_str(&format!("  \"{}\" [label=\"{}\"];\n", id, label));
            }
        }

        for (_id, node) in self.tree.arena().iter() {
            for child in node.children() {
                let child_id = node_id(&child);
                let parent_id = node_id(node);
                dot.push_str(&format!("  \"{}\" -> \"{}\";\n", parent_id, child_id));
            }
        }

        dot.push('}');
        dot
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
        let mut out: IndexMap<NodeId, Option<POut>> =
            IndexMap::with_capacity(self.tree.arena().len());
        for (id, node) in self.tree.arena().iter() {
            let p_out = self.payloads[id]
                .as_ref()
                .and_then(|p_in| pass.transform(node, id.clone(), p_in));
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
        let out_vec: Vec<(NodeId, Option<POut>)> = self
            .tree
            .arena()
            .into_par_iter()
            .map(|(id, node)| {
                let maybe = self.payloads[id]
                    .as_ref()
                    .and_then(|p_in| pass.transform(node, id.clone(), p_in));
                (id.clone(), maybe)
            })
            .collect();
        let out: IndexMap<NodeId, Option<POut>> = out_vec.into_iter().collect();
        Ir {
            tree: self.tree.clone(),
            payloads: out,
        }
    }
}
pub trait LocalPass<B, PIn, POut> 
where
    B: SnarkBackend,
    PIn: Payload,
    POut: Payload,
{
    fn transform(&self, node: &Node<B>, id: NodeId, payload: &PIn) -> Option<POut>;
}
