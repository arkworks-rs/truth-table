use ark_piop::SnarkBackend;
use indexmap::IndexMap;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::irs::{
    nodes::{IsNode, Node, NodeId, PlanNode},
    payloads::{EmptyPayload, HintDFPayload},
    tree::{Payload, Tree},
};
pub struct Ir<B: SnarkBackend, Pd: Payload> {
    tree: Tree<B>,
    payloads: IndexMap<NodeId, Option<Pd>>,
}

/// The initial Intermediate Representation with empty payloads.
///
/// This IR represents the starting point of the prover's pipeline, where the proof tree nodes contain no additional information.
pub type InitialIr<B> = Ir<B, EmptyPayload>;
/// The planned Intermediate Representation with hint dataframe payloads.
///
/// This IR represents the stage in the prover's pipeline where the proof tree nodes contain hint dataframes (or logical plans) that will be executed in later stages.
pub type PlannedIr<B> = Ir<B, HintDFPayload>;

impl<Pd: Payload, B: SnarkBackend> Ir<B, Pd> {
    pub fn new(tree: Tree<B>, payloads: IndexMap<NodeId, Option<Pd>>) -> Self {
        Self { tree, payloads }
    }

    pub fn new_empty(tree: Tree<B>) -> Self {
        let payloads = tree
            .arena()
            .keys()
            .map(|id| (*id, None))
            .collect::<IndexMap<_, _>>();
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

    pub fn set_payload_for_node(&mut self, node_id: NodeId, payload: Option<Pd>) {
        self.payloads.insert(node_id, payload);
    }

    pub fn payloads_mut(&mut self) -> &mut IndexMap<NodeId, Option<Pd>> {
        &mut self.payloads
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
                                "<{}<BR/><FONT COLOR=\"red\">{}</FONT>>",
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
            let mut attrs = Vec::new();
            if html {
                attrs.push(format!("label={}", label));
            } else {
                attrs.push(format!("label=\"{}\"", label));
            }
            match node.as_ref() {
                Node::Gadget(_) => attrs.push("color=\"purple\"".to_string()),
                Node::Plan(PlanNode::LpBased(_)) => attrs.push("color=\"blue\"".to_string()),
                Node::Plan(PlanNode::ExprBased(_)) => attrs.push("color=\"green\"".to_string()),
            };
            dot.push_str(&format!("  \"{}\" [{}];\n", id, attrs.join(", ")));
        }

        for (_id, node) in self.tree.arena().iter() {
            for child in node.children() {
                dot.push_str(&format!("  \"{}\" -> \"{}\";\n", node.id(), child.id()));
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
        PIn: Clone,
        POut: Payload,
        P: LocalPass<B, PIn, POut>,
    {
        let mut out: IndexMap<NodeId, Option<POut>> =
            IndexMap::with_capacity(self.tree.arena().len());
        for (id, node) in self.tree.arena().iter() {
            let input_payload = self.payloads[id]
                .as_ref()
                .cloned()
                .or_else(|| pass.fallback_payload(node, id.clone()));
            let p_out = pass.transform(node, id.clone(), input_payload.as_ref());
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
                let maybe = pass.transform(node, id.clone(), self.payloads[id].as_ref());
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
    fn transform(&self, node: &Node<B>, id: NodeId, payload: Option<&PIn>) -> Option<POut>;

    /// Optional fallback payload to use when the input payload is missing. By default,
    /// no fallback is provided and nodes without an input payload are skipped.
    fn fallback_payload(&self, _node: &Node<B>, _id: NodeId) -> Option<PIn> {
        None
    }
}
