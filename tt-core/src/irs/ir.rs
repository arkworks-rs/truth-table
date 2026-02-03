use ark_piop::SnarkBackend;
use indexmap::IndexMap;
use tracing::debug;

use crate::irs::{
    nodes::{IsNode, Node, NodeId, PlanNode},
    tree::{Payload, Tree},
};
use std::sync::Arc;
pub struct Ir<B: SnarkBackend, Pd: Payload> {
    tree: Tree<B>,
    payloads: IndexMap<NodeId, Option<Pd>>,
}

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
        dot.push_str("  subgraph cluster_legend {\n");
        dot.push_str("    rank=\"sink\";\n");
        dot.push_str("    label=\"Legend\";\n");
        dot.push_str("    labelloc=\"b\";\n");
        dot.push_str("    style=\"rounded\";\n");
        dot.push_str("    color=\"gray\";\n");
        dot.push_str("    fontcolor=\"gray\";\n");
        dot.push_str(
            "    legend_plan_lp [label=<Plan (LP)<BR/><FONT COLOR=\"red\">PlanPayload(example)</FONT>>, color=\"blue\"];\n",
        );
        dot.push_str(
            "    legend_plan_expr [label=<Plan (Expr)<BR/><FONT COLOR=\"red\">PlanPayload(example)</FONT>>, color=\"green\"];\n",
        );
        dot.push_str(
            "    legend_gadget [label=<Gadget<BR/><FONT COLOR=\"red\">GadgetPayload{key: example}</FONT>>, color=\"purple\"];\n",
        );
        dot.push_str("  }\n");

        for (id, node) in self.tree.arena().iter() {
            let display = node.display();
            let display_html = escape_html(&display).replace('\n', "<BR ALIGN=\"LEFT\"/>");
            let label = if show_payload {
                if let Some(Some(payload)) = self.payloads.get(id) {
                    let payload_str =
                        escape_html(&format!("{}", payload)).replace('\n', "<BR ALIGN=\"LEFT\"/>");
                    if payload_str.is_empty() {
                        format!("<{}>", display_html)
                    } else {
                        format!(
                            "<{}<BR/><FONT COLOR=\"red\">{}</FONT>>",
                            display_html, payload_str
                        )
                    }
                } else {
                    format!("<{}>", display_html)
                }
            } else {
                format!("<{}>", display_html)
            };
            let mut attrs = Vec::new();
            attrs.push(format!("label={}", label));
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
    fn ordered_nodes(&self, order: PassOrder) -> Vec<(NodeId, Arc<Node<B>>)> {
        match order {
            PassOrder::PostOrder => self
                .tree
                .arena()
                .iter()
                .map(|(id, node)| (*id, node.clone()))
                .collect(),
            PassOrder::PreOrder => {
                fn walk<B: SnarkBackend>(
                    node: Arc<Node<B>>,
                    out: &mut Vec<(NodeId, Arc<Node<B>>)>,
                ) {
                    let id = node.id();
                    out.push((id, node.clone()));
                    for child in node.children() {
                        walk(child, out);
                    }
                }
                let mut out = Vec::with_capacity(self.tree.arena().len());
                walk(self.tree.root().clone(), &mut out);
                out
            }
        }
    }

    pub fn apply_local_pass_sequential<POut, P>(&self, pass: &P) -> Ir<B, POut>
    where
        PIn: Clone,
        POut: Payload,
        P: LocalPass<B, PIn, POut>,
    {
        let mut out: IndexMap<NodeId, Option<POut>> =
            IndexMap::with_capacity(self.tree.arena().len());
        for (id, node) in self.ordered_nodes(pass.order()) {
            let input_payload = self
                .payloads
                .get(&id)
                .as_ref()
                .and_then(|opt| opt.as_ref())
                .cloned()
                .or_else(|| pass.fallback_payload(&node, id));
            debug!(
                node_id = ?id,
                node_name = %node.name(),
                has_payload = input_payload.is_some(),
                "pass.transform start"
            );
            let p_out = pass.transform(&node, id, input_payload.as_ref());
            debug!(
                node_id = ?id,
                node_name = %node.name(),
                produced = p_out.is_some(),
                "pass.transform end"
            );
            out.insert(id, p_out);
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
        if matches!(pass.order(), PassOrder::PreOrder) {
            panic!("PreOrder passes are not supported in parallel traversal");
        }
        use rayon::prelude::*;
        let out_vec: Vec<(NodeId, Option<POut>)> = self
            .tree
            .arena()
            .into_par_iter()
            .map(|(id, node)| {
                let input_payload = self.payloads.get(id).and_then(|opt| opt.as_ref());
                debug!(
                    node_id = ?id,
                    has_payload = input_payload.is_some(),
                    "pass.transform start"
                );
                // Some optimizer passes can temporarily hide subtrees (e.g. mode switches).
                // Those detached nodes may still exist in arena but have no payload entry.
                // Skip transforming them in parallel traversal.
                let maybe = if self.payloads.contains_key(id) {
                    pass.transform(node, *id, input_payload)
                } else {
                    None
                };
                debug!(
                    node_id = ?id,
                    produced = maybe.is_some(),
                    "pass.transform end"
                );
                (*id, maybe)
            })
            .collect();
        let out: IndexMap<NodeId, Option<POut>> = out_vec.into_iter().collect();
        Ir {
            tree: self.tree.clone(),
            payloads: out,
        }
    }
}
#[derive(Copy, Clone)]
pub enum PassOrder {
    PreOrder,
    PostOrder,
}
pub trait LocalPass<B, PIn, POut>
where
    B: SnarkBackend,
    PIn: Payload,
    POut: Payload,
{
    fn transform(&self, node: &Node<B>, id: NodeId, payload: Option<&PIn>) -> Option<POut>;

    fn order(&self) -> PassOrder;

    /// Optional fallback payload to use when the input payload is missing. By default,
    /// no fallback is provided and nodes without an input payload are skipped.
    fn fallback_payload(&self, _node: &Node<B>, _id: NodeId) -> Option<PIn> {
        None
    }
}
