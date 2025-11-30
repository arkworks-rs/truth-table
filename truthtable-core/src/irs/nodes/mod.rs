use std::{any::Any, sync::Arc};

use ark_piop::{SnarkBackend, errors::SnarkResult};
use arrow_schema::SchemaRef;
use datafusion_common::Statistics;
use datafusion_expr::{Expr, LogicalPlan};
use derivative::Derivative;
use indexmap::IndexMap;

use crate::irs::nodes::{cost::ProvingCost, gadget::GadgetAncestry, hints::HintDF};
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
    /// Returns the unique identifier of this node.
    fn id(&self) -> NodeId;
    /// Returns this node's children.
    fn children(&self) -> Vec<Node<B>>;
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
    fn gadget(&self) -> Node<B>;
    /// Outputs the DataFrame resulting from executing this plan node.
    fn output(&self) -> HintDF;
}

impl<B: SnarkBackend> Node<B> {
    pub(crate) fn from_lp(plan: LogicalPlan) -> Self {
        todo!()
    }
    pub(crate) fn from_expr(expr: &Expr, parent: Option<NodeId>) -> Self {
        todo!()
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
    /// Returns this node
    fn id(&self) -> NodeId {
        match &self {
            Node::Plan(plan_node) => plan_node.id(),
            Node::Gadget(gadget_node) => gadget_node.id(),
        }
    }
    /// Returns the children plan nodes of this plan node. Note that the child of a plan node is a plan node, not a gadget.
    fn children(&self) -> Vec<Node<B>> {
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
    /// Returns this node
    fn id(&self) -> NodeId {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.id(),
            PlanNode::ExprBased(expr_node) => expr_node.id(),
        }
    }
    /// Returns the children plan nodes of this plan node. Note that the child of a plan node is a plan node, not a gadget.
    fn children(&self) -> Vec<Node<B>> {
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
    fn gadget(&self) -> Node<B> {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.gadget(),
            PlanNode::ExprBased(expr_node) => expr_node.gadget(),
        }
    }

    /// Outputs the DataFrame resulting from executing this plan node.
    fn output(&self) -> HintDF {
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
    fn ancestry(&self) -> GadgetAncestry;
}
pub trait IsLpNode<B>: IsPlanNode<B>
where
    B: SnarkBackend,
{
    /// Constructs a proof plan node from a DataFusion logical plan.
    // TODO: We might not need ctx here
    fn from_lp(_plan: LogicalPlan) -> Self
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
    fn from_expr(_expr: Expr, parent: Option<Node<B>>) -> Self
    where
        Self: Sized;

    fn expr(&self) -> Expr;

    fn parent(&self) -> PlanNode<B>
    where
        Self: Sized;

    fn ctx_lp_node(&self) -> Arc<dyn IsLpNode<B>>
    where
        Self: Sized,
    {
        todo!()
    }
}
