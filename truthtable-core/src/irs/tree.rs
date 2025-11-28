use super::nodes::{cost::ProvingCost, id::NodeId};
use crate::irs::nodes;
use crate::irs::nodes::hints::HintDF;
use crate::irs::nodes::plan::{exprs, lps};
use arithmetic::ctx::SharedCtx;
use ark_piop::SnarkBackend;
use ark_piop::errors::SnarkResult;
use ark_std::fmt::Debug;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use datafusion_common::Statistics;
use indexmap::IndexMap;
use std::{any::Any, sync::Arc};

fn build_arena<B>(root: &Arc<dyn PlanNode<B>>) -> IndexMap<NodeId, Arc<dyn Node<B>>>
where
    B: SnarkBackend,
{
    fn visit<B>(node: &Arc<dyn Node<B>>, arena: &mut IndexMap<NodeId, Arc<dyn Node<B>>>)
    where
        B: SnarkBackend,
    {
        if let Some(plan) = node.as_plan_node() {
            for child in plan.children() {
                visit(&child, arena);
            }
        }
        arena.insert(node.id(), Arc::clone(node));
    }

    let mut arena = IndexMap::new();
    let root_node: Arc<dyn Node<B>> = Arc::clone(root) as Arc<dyn Node<B>>;
    visit(&root_node, &mut arena);
    arena
}

/// The abstraction of a tree structure used in intermediate representations
#[derive(Debug)]
pub struct Tree<B>
where
    B: SnarkBackend,
{
    root: Arc<dyn Node<B>>,
    arena: IndexMap<NodeId, Arc<dyn Node<B>>>,
}

impl<B> Clone for Tree<B>
where
    B: SnarkBackend,
{
    fn clone(&self) -> Self {
        Self {
            root: Arc::clone(&self.root),
            arena: self.arena.clone(),
        }
    }
}
impl<B> Tree<B>
where
    B: SnarkBackend,
{
    pub fn new(root: Arc<dyn Node<B>>, arena: IndexMap<NodeId, Arc<dyn Node<B>>>) -> Self {
        Self { root, arena }
    }

    /// Get the root node of this tree.
    pub fn root(&self) -> Arc<dyn Node<B>> {
        Arc::clone(&self.root)
    }

    /// Get the root node as a plan node, if it is one.
    pub fn root_plan(&self) -> Option<&dyn PlanNode<B>> {
        self.root.as_plan_node()
    }

    /// Get the arena of nodes in this tree.
    pub fn arena(&self) -> &IndexMap<NodeId, Arc<dyn Node<B>>> {
        &self.arena
    }

    /// Get a node by its ID from the arena.
    pub fn get_node(&self, node_id: &NodeId) -> Option<&Arc<dyn Node<B>>> {
        self.arena.get(node_id)
    }

    /// Display the tree in Graphviz DOT format.
    pub fn display_graphviz(&self, inner: bool) -> String {
        todo!()
    }

    pub fn from_logical_plan(lp: &LogicalPlan) -> Self {
        let plan_root: Arc<dyn PlanNode<B>> = match lp {
            LogicalPlan::TableScan(_) => Arc::new(
                <lps::table_scan::ProverNode as LpNode<B>>::from_lp(lp.clone()),
            ),
            LogicalPlan::Projection(_) => Arc::new(
                <lps::projection::ProverNode<B> as LpNode<B>>::from_lp(lp.clone()),
            ),
            LogicalPlan::Filter(_) => Arc::new(<lps::filter::ProverNode<B> as LpNode<B>>::from_lp(
                lp.clone(),
            )),
            _ => todo!(),
        };
        let root: Arc<dyn Node<B>> = plan_root.clone();
        Self {
            root,
            arena: build_arena(&plan_root),
        }
    }

    pub fn from_expr(expr: &Expr, parent: Option<NodeId>) -> Self {
        let plan_root: Arc<dyn PlanNode<B>> = match expr {
            Expr::Column(_) => Arc::new(<exprs::column::ProverNode as ExprNode<B>>::from_expr(
                expr.clone(),
                parent,
            )),
            Expr::Literal(_) => Arc::new(<exprs::literal::ProverNode as ExprNode<B>>::from_expr(
                expr.clone(),
                parent,
            )),
            Expr::BinaryExpr(_) => Arc::new(
                <exprs::binary_expr::ProverNode<B> as ExprNode<B>>::from_expr(expr.clone(), parent),
            ),
            _ => todo!(),
        };
        let root: Arc<dyn Node<B>> = plan_root.clone();
        Self {
            root,
            arena: build_arena(&plan_root),
        }
    }
}

pub trait Payload: Debug + 'static {}

pub trait Node<B>: Any + Send + Sync + Debug
where
    B: SnarkBackend,
{
    /// Returns the unique identifier of this node.
    fn id(&self) -> NodeId;
    /// Returns the human-readable name of this node.
    fn name(&self) -> String;
    /// Returns a human-readable representation of this node.
    fn display(&self) -> String {
        self.name()
    }
    /// Estimates the proving cost of this node given statistics and schema.
    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;

    /// Returns this node as a plan node if applicable.
    ///
    /// Plan-node implementations should return `Some(self)` (appropriately
    /// upcast), while non-plan nodes should return `None`. This allows callers
    /// that only have a `&dyn Node` (e.g., from `Ir::apply_local_pass_*`) to
    /// recover plan-specific behavior such as `output()`.
    fn as_plan_node(&self) -> Option<&dyn PlanNode<B>>;

    /// Returns this node as a gadget node if applicable.
    ///
    /// Gadget-node implementations should return `Some(self)` (upcast), while
    /// non-gadget nodes should return `None`. This mirrors `as_plan_node` and
    /// lets callers recover gadget-specific functionality when they only hold
    /// a `&dyn Node`.
    fn as_gadget_node(&self) -> Option<&dyn Gadget<B>>;
}

pub trait Gadget<B>: Node<B> + Any + Send + Sync
where
    B: SnarkBackend,
{
    /// Returns the children gadgets of this gadget. Note that the child of a gadget is a gadget, not a plan node.
    fn children(&self) -> Vec<Arc<Self>>
    where
        Self: Sized;
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>>
    where
        Self: Sized,
    {
        self.children().into_iter().map(|_| None).collect()
    }
    /// Runs the gadget prover
    fn prove() -> SnarkResult<()>
    where
        Self: Sized;

    fn hints(&self) -> IndexMap<String, HintDF>;
}

pub trait PlanNode<B>: Node<B> + Any + Send + Sync
where
    B: SnarkBackend,
{
    /// Returns the children plan nodes of this plan node. Note that the child of a plan node is a plan node, not a gadget.
    fn children(&self) -> Vec<Arc<dyn Node<B>>>;
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }
    /// Returns the gadget associated with this plan node. Note that each plan node has exactly one gadget.
    fn gadget(&self) -> Arc<dyn Gadget<B>>;

    /// Outputs the DataFrame resulting from executing this plan node.
    fn output(&self) -> HintDF;
}

pub trait LpNode<B>: PlanNode<B> + Any + Send + Sync
where
    B: SnarkBackend,
{
    /// Constructs a proof plan node from a DataFusion logical plan.
    // TODO: We might not need ctx here
    fn from_lp(_plan: LogicalPlan) -> Self
    where
        Self: Sized;
}

pub trait ExprNode<B>: PlanNode<B> + Any + Send + Sync
where
    B: SnarkBackend,
{
    /// Constructs a proof plan node from a DataFusion expression and its parent
    /// logical plan.
    // TODO: We might not need ctx and parent_logical_plan here
    fn from_expr(_expr: Expr, parent: Option<NodeId>) -> Self
    where
        Self: Sized;

    fn parent(&self) -> Arc<dyn PlanNode<B>>
    where
        Self: Sized;

    fn ctx_lp_node(&self) -> Arc<dyn LpNode<B>>
    where
        Self: Sized,
    {
        todo!()
    }
}
