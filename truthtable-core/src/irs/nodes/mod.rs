use std::{
    any::Any,
    hash::{Hash, Hasher},
    sync::{Arc, Weak},
};

use ark_piop::{SnarkBackend, errors::SnarkResult};
use arrow_schema::SchemaRef;
use datafusion_common::Statistics;
use datafusion_expr::{Expr, LogicalPlan};
use derivative::Derivative;
use indexmap::IndexMap;

use crate::irs::nodes::{
    cost::ProvingCost,
    gadget::GadgetAncestry,
    hints::HintDF,
    plan::{
        exprs::{binary_expr, column, literal},
        lps::{filter, projection, table_scan},
    },
};
pub mod cost;
pub mod gadget;
pub mod hints;
pub mod plan;

pub type NodeId = u64;
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub enum Node<B: SnarkBackend> {
    Plan(PlanNode<B>),
    Gadget(Arc<dyn IsGadgetNode<B>>),
}
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub enum PlanNode<B: SnarkBackend> {
    LpBased(Arc<dyn IsLpNode<B>>),
    ExprBased(Arc<dyn IsExprNode<B>>),
}

impl<B: SnarkBackend> Hash for Node<B> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Node::Plan(plan) => {
                state.write_u8(0);
                plan.hash(state);
            }
            Node::Gadget(gadget) => {
                state.write_u8(1);
                std::ptr::hash(Arc::as_ptr(gadget), state);
            }
        }
    }
}

impl<B: SnarkBackend> Hash for PlanNode<B> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PlanNode::LpBased(node) => {
                state.write_u8(0);
                std::ptr::hash(Arc::as_ptr(node), state);
            }
            PlanNode::ExprBased(node) => {
                state.write_u8(1);
                std::ptr::hash(Arc::as_ptr(node), state);
            }
        }
    }
}

/// Common interface across all node kinds.
pub trait IsNode<B>: Any + Send + Sync
where
    B: SnarkBackend,
{
    /// Returns the human-readable name of this node.
    fn name(&self) -> String;
    /// Returns a human-readable representation of this node.
    fn display(&self) -> String {
        self.name()
    }
    /// Estimates the proving cost of this node given statistics and schema.
    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;
    /// Returns this node's children.
    fn children(&self) -> Vec<Arc<Node<B>>>;
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }
}

/// Shared plan-node interface (both LP and expr-based).
pub trait IsPlanNode<B>: IsNode<B>
where
    B: SnarkBackend,
{
    /// Returns the gadget associated with this plan node. Note that each plan node has exactly one gadget.
    fn gadget(&self) -> Arc<Node<B>>;
    /// Outputs the DataFrame resulting from executing this plan node.
    fn output(&self) -> HintDF;
}

impl<B: SnarkBackend> Node<B> {
    pub(crate) fn from_lp(plan: LogicalPlan) -> Arc<Self> {
        match plan.clone() {
            LogicalPlan::Projection(_) => Arc::new_cyclic(|weak_self| {
                let node = projection::ProverNode::from_lp(plan.clone(), weak_self.clone());
                Node::Plan(PlanNode::LpBased(Arc::new(node)))
            }),

            LogicalPlan::TableScan(_) => Arc::new_cyclic(|weak_self| {
                let node = table_scan::ProverNode::from_lp(plan.clone(), weak_self.clone());
                Node::Plan(PlanNode::LpBased(Arc::new(node)))
            }),
            LogicalPlan::Filter(_) => Arc::new_cyclic(|weak_self| {
                let node = filter::ProverNode::from_lp(plan.clone(), weak_self.clone());
                Node::Plan(PlanNode::LpBased(Arc::new(node)))
            }),
            _ => todo!(),
        }
    }
    pub(crate) fn from_expr(
        expr: &Expr,
        parent: Option<Weak<Node<B>>>,
        scope: Arc<Node<B>>,
    ) -> Arc<Self> {
        match expr.clone() {
            Expr::Column(_) => Arc::new_cyclic(|weak_self| {
                let node = column::ProverNode::from_expr(
                    expr.clone(),
                    weak_self.clone(),
                    parent.clone(),
                    scope.clone(),
                );
                Node::Plan(PlanNode::ExprBased(Arc::new(node)))
            }),

            Expr::Literal(_) => Arc::new_cyclic(|weak_self| {
                let node = literal::ProverNode::from_expr(
                    expr.clone(),
                    weak_self.clone(),
                    parent.clone(),
                    scope.clone(),
                );
                Node::Plan(PlanNode::ExprBased(Arc::new(node)))
            }),
            Expr::BinaryExpr(_) => Arc::new_cyclic(|weak_self| {
                let node = binary_expr::ProverNode::from_expr(
                    expr.clone(),
                    weak_self.clone(),
                    parent.clone(),
                    scope.clone(),
                );
                Node::Plan(PlanNode::ExprBased(Arc::new(node)))
            }),

            _ => todo!(),
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for Node<B> {
    /// Returns the human-readable name of this node.
    fn name(&self) -> String {
        match &self {
            Node::Plan(plan_node) => plan_node.name(),
            Node::Gadget(gadget_node) => gadget_node.name(),
        }
    }
    /// Returns a human-readable representation of this node.
    fn display(&self) -> String {
        match &self {
            Node::Plan(plan_node) => plan_node.display(),
            Node::Gadget(gadget_node) => gadget_node.display(),
        }
    }
    /// Estimates the proving cost of this node given statistics and schema.
    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost {
        match &self {
            Node::Plan(plan_node) => plan_node.cost(statistics, schema),
            Node::Gadget(gadget_node) => gadget_node.cost(statistics, schema),
        }
    }

    /// Returns the children plan nodes of this plan node. Note that the child of a plan node is a plan node, not a gadget.
    fn children(&self) -> Vec<Arc<Node<B>>> {
        match &self {
            Node::Plan(plan_node) => plan_node.children(),
            Node::Gadget(gadget_node) => gadget_node.children(),
        }
    }
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        match &self {
            Node::Plan(plan_node) => plan_node.child_edge_labels(),
            Node::Gadget(gadget_node) => gadget_node.child_edge_labels(),
        }
    }
}

impl<B: SnarkBackend> PlanNode<B> {
    /// Returns the human-readable name of this node.
    fn name(&self) -> String {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.name(),
            PlanNode::ExprBased(expr_node) => expr_node.name(),
        }
    }
    /// Returns a human-readable representation of this node.
    fn display(&self) -> String {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.display(),
            PlanNode::ExprBased(expr_node) => expr_node.display(),
        }
    }
    /// Estimates the proving cost of this node given statistics and schema.
    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.cost(statistics, schema),
            PlanNode::ExprBased(expr_node) => expr_node.cost(statistics, schema),
        }
    }
    /// Returns the children plan nodes of this plan node. Note that the child of a plan node is a plan node, not a gadget.
    fn children(&self) -> Vec<Arc<Node<B>>> {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.children(),
            PlanNode::ExprBased(expr_node) => expr_node.children(),
        }
    }
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.child_edge_labels(),
            PlanNode::ExprBased(expr_node) => expr_node.child_edge_labels(),
        }
    }

    /// Returns the gadget associated with this plan node. Note that each plan node has exactly one gadget.
    fn gadget(&self) -> Arc<Node<B>> {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.gadget(),
            PlanNode::ExprBased(expr_node) => expr_node.gadget(),
        }
    }

    /// Outputs the DataFrame resulting from executing this plan node.
    pub fn output(&self) -> HintDF {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.output(),
            PlanNode::ExprBased(expr_node) => expr_node.output(),
        }
    }
}

pub trait IsGadgetNode<B>: IsNode<B>
where
    B: SnarkBackend,
{
    /// Runs the gadget prover
    fn prove() -> SnarkResult<()>
    where
        Self: Sized;

    fn hints(&self) -> IndexMap<String, HintDF>;
    // Returns the ancestry of this gadget node.
    // Serves as a unique identifier for the gadget
    fn ancestry(&self) -> GadgetAncestry;
}
pub trait IsLpNode<B>: IsPlanNode<B>
where
    B: SnarkBackend,
{
    /// Constructs a proof plan node from a DataFusion logical plan.
    // TODO: We might not need ctx here
    fn from_lp(_plan: LogicalPlan, self_ref: Weak<Node<B>>) -> Self
    where
        Self: Sized;

    fn lp(&self) -> LogicalPlan;
}

pub trait IsExprNode<B>: IsPlanNode<B>
where
    B: SnarkBackend,
{
    /// Constructs a proof plan node from a DataFusion expression and its parent
    /// logical plan.
    // TODO: We might not need ctx and parent_logical_plan here
    fn from_expr(
        _expr: Expr,
        self_ref: Weak<Node<B>>,
        parent: Option<Weak<Node<B>>>,
        scope: Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized;

    fn expr(&self) -> Expr;

    fn parent(&self) -> PlanNode<B>
    where
        Self: Sized;

    fn scope(&self) -> Arc<Node<B>>
    where
        Self: Sized;

    fn ctx_lp_node(&self) -> Arc<dyn IsLpNode<B>>
    where
        Self: Sized,
    {
        todo!()
    }
}
