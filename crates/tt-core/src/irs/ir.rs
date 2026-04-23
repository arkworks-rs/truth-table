//! [`Ir`] — tree + per-node payload map — and the [`LocalPass`] trait every
//! pass implements.
//!
//! The pipeline is a chain of [`LocalPass`]es: each takes an `Ir<B, PIn>`,
//! visits every node in [`PassOrder::PreOrder`] or [`PassOrder::PostOrder`],
//! and returns an `Ir<B, POut>`. The tree is shared across stages; only the
//! payload type changes. Passes come in two flavors depending on whether they
//! need global state per node:
//!
//! - [`Ir::apply_local_pass_sequential`] — visit nodes in order, on one thread.
//! - [`Ir::apply_local_pass_parallel`] — fan out via rayon; post-order only.

use ark_piop::SnarkBackend;
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use tracing::{debug, debug_span};

use crate::irs::{
    nodes::{IsNode, Node, NodeId, PlanNode},
    payloads::EmptyPayload,
    tree::{Payload, Tree},
};
use std::sync::Arc;

/// The intermediate representation: a shared [`Tree`] paired with one payload
/// per node for the current pipeline stage.
///
/// `B` is the SNARK backend; `Pd` is the pass-specific payload type.
/// `payloads[id]` is `None` while the node hasn't been touched yet (e.g. in
/// the starting [`EmptyPayload`] stage) or when a pass chose to produce no
/// output for that node.
pub struct Ir<B: SnarkBackend, Pd: Payload> {
    tree: Tree<B>,
    payloads: IndexMap<NodeId, Option<Pd>>,
}

impl<Pd: Payload + Clone, B: SnarkBackend> Clone for Ir<B, Pd> {
    fn clone(&self) -> Self {
        Self {
            tree: self.tree.clone(),
            payloads: self.payloads.clone(),
        }
    }
}

impl<Pd: Payload, B: SnarkBackend> Ir<B, Pd> {
    /// Construct an IR from an existing tree and fully populated payload map.
    pub fn new(tree: Tree<B>, payloads: IndexMap<NodeId, Option<Pd>>) -> Self {
        Self { tree, payloads }
    }

    /// Construct an IR from `tree` with every node mapped to `None`.
    pub fn new_empty(tree: Tree<B>) -> Self {
        let payloads = tree
            .arena()
            .keys()
            .map(|id| (*id, None))
            .collect::<IndexMap<_, _>>();
        Self { tree, payloads }
    }

    /// Borrow the node tree.
    pub fn tree(&self) -> &Tree<B> {
        &self.tree
    }

    /// Borrow the per-node payload map.
    pub fn payloads(&self) -> &IndexMap<NodeId, Option<Pd>> {
        &self.payloads
    }

    /// Get the payload for a specific node, or `None` if the node is missing
    /// or has no payload in this stage.
    pub fn payload_for_node(&self, node_id: &NodeId) -> Option<&Pd> {
        self.payloads.get(node_id).and_then(|opt| opt.as_ref())
    }

    /// Overwrite the payload for a specific node.
    pub fn set_payload_for_node(&mut self, node_id: NodeId, payload: Option<Pd>) {
        self.payloads.insert(node_id, payload);
    }

    /// Mutable borrow of the per-node payload map.
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

impl<B: SnarkBackend> Ir<B, EmptyPayload> {
    /// Build the starting-point IR from a DataFusion logical plan.
    ///
    /// All payloads are `None`; the first pass in the pipeline fills them in.
    pub fn from_logical_plan(lp: &LogicalPlan) -> Self {
        Self::new_empty(Tree::from_logical_plan(lp))
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

    /// Run a [`LocalPass`] over every node on one thread, in the pass's
    /// preferred [`PassOrder`], and return a new IR carrying the pass's output
    /// payload type.
    ///
    /// Used for passes that need sequential state (e.g. accumulating into a
    /// single `ArgProver`) or pre-order traversal, which the parallel version
    /// doesn't support.
    pub fn apply_local_pass_sequential<POut, P>(&self, pass: &P) -> Ir<B, POut>
    where
        POut: Payload,
        P: LocalPass<B, PIn, POut>,
    {
        pass.begin_pass(self);
        let mut out: IndexMap<NodeId, Option<POut>> =
            IndexMap::with_capacity(self.tree.arena().len());
        for (id, node) in self.ordered_nodes(pass.order()) {
            let existing_payload = self.payloads.get(&id).and_then(|opt| opt.as_ref());
            let fallback_payload = if existing_payload.is_none() {
                pass.fallback_payload(&node, id)
            } else {
                None
            };
            let input_payload = existing_payload.or(fallback_payload.as_ref());
            let span = debug_span!(
                "pass.transform",
                pass = pass.name(),
                node_id = ?id,
                node_name = %node.name(),
                has_payload = input_payload.is_some()
            );
            let _span_guard = span.enter();
            let p_out = pass.transform(&node, id, input_payload);
            debug!(
                node_name = %node.name(),
                produced = p_out.is_some(),
                "pass.transform"
            );
            out.insert(id, p_out);
        }
        pass.end_pass();
        Ir {
            tree: self.tree.clone(),
            payloads: out,
        }
    }

    /// Run a [`LocalPass`] over every node in parallel via rayon.
    ///
    /// Only post-order traversal is supported; passing a [`PassOrder::PreOrder`]
    /// pass panics, because the parent-before-child dependency cannot be
    /// preserved under fan-out.
    pub fn apply_local_pass_parallel<POut, P>(&self, pass: &P) -> Ir<B, POut>
    where
        PIn: Payload + Send + Sync,
        POut: Payload + Send + Sync,
        P: LocalPass<B, PIn, POut> + Sync,
    {
        if matches!(pass.order(), PassOrder::PreOrder) {
            panic!("PreOrder passes are not supported in parallel traversal");
        }
        pass.begin_pass(self);
        use rayon::prelude::*;
        let out_vec: Vec<(NodeId, Option<POut>)> = self
            .tree
            .arena()
            .into_par_iter()
            .map(|(id, node)| {
                let input_payload = self.payloads.get(id).and_then(|opt| opt.as_ref());
                let span = debug_span!(
                    "pass.transform",
                    pass = pass.name(),
                    node_id = ?id,
                    node_name = %node.name(),
                    has_payload = input_payload.is_some()
                );
                let _span_guard = span.enter();
                // Some optimizer passes can temporarily hide subtrees (e.g. mode switches).
                // Those detached nodes may still exist in arena but have no payload entry.
                // Skip transforming them in parallel traversal.
                let maybe = if self.payloads.contains_key(id) {
                    pass.transform(node, *id, input_payload)
                } else {
                    None
                };
                debug!(
                    node_name = %node.name(),
                    produced = maybe.is_some(),
                    "pass.transform"
                );
                (*id, maybe)
            })
            .collect();
        pass.end_pass();
        let out: IndexMap<NodeId, Option<POut>> = out_vec.into_iter().collect();
        Ir {
            tree: self.tree.clone(),
            payloads: out,
        }
    }
}
/// Traversal order for a [`LocalPass`].
///
/// Post-order visits children before their parent — the default for most IR
/// passes, and the only order the parallel traversal supports. Pre-order is
/// used by a few passes (gadget planning and gadget initialization) that must
/// emit parent state before descending.
#[derive(Copy, Clone)]
pub enum PassOrder {
    /// Visit each node before its children.
    PreOrder,
    /// Visit each node after its children.
    PostOrder,
}

/// One stage of the prover or verifier pipeline.
///
/// A pass reads a node plus its input payload and produces the next stage's
/// payload — `None` means "skip this node". Each pass declares its preferred
/// [`PassOrder`] and whether it has per-pass setup / teardown work via
/// [`LocalPass::begin_pass`] / [`LocalPass::end_pass`].
pub trait LocalPass<B, PIn, POut>
where
    B: SnarkBackend,
    PIn: Payload,
    POut: Payload,
{
    /// Produce the output payload for `node`.
    ///
    /// `payload` is the input stage's payload for this node, or `None` either
    /// because no earlier pass filled it in (and [`Self::fallback_payload`]
    /// didn't supply one) or because the node was detached by an optimizer
    /// mode switch.
    fn transform(&self, node: &Node<B>, id: NodeId, payload: Option<&PIn>) -> Option<POut>;

    /// Declare the traversal order this pass needs.
    fn order(&self) -> PassOrder;

    /// Optional fallback payload to use when the input payload is missing. By default,
    /// no fallback is provided and nodes without an input payload are skipped.
    fn fallback_payload(&self, _node: &Node<B>, _id: NodeId) -> Option<PIn> {
        None
    }
    /// Optional setup hook called once before pass traversal.
    fn begin_pass(&self, _ir: &Ir<B, PIn>) {}
    /// Optional teardown hook called once after pass traversal.
    fn end_pass(&self) {}
    /// Static name for tracing and bench-stats logging.
    fn name(&self) -> &'static str;
}
