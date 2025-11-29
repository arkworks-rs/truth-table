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
// pub mod plan;

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

impl<B: SnarkBackend> Node<B> {
    /// Returns the human-readable name of this node.
    fn name(&self) -> String {
        todo!()
    }
    /// Returns a human-readable representation of this node.
    fn display(&self) -> String {
        self.name()
    }
    /// Estimates the proving cost of this node given statistics and schema.
    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost {
        todo!()
    }
    /// Returns this node
    fn id(&self) -> NodeId {
        todo!()
    }
    /// Returns the children plan nodes of this plan node. Note that the child of a plan node is a plan node, not a gadget.
    fn children(&self) -> Vec<Node<B>> {
        match &self {
            Node::Plan(plan_node) => match plan_node {
                PlanNode::LpBased(lp_node) => lp_node.children(),
                PlanNode::ExprBased(expr_node) => expr_node.children(),
            },
            Node::Gadget(gadget_node) => gadget_node.children(),
        }
    }
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }

    pub(crate) fn from_lp(plan: LogicalPlan) -> Self {
        todo!()
    }
    pub(crate) fn from_expr(expr: &Expr, parent: Option<NodeId>) -> Self {
        todo!()
    }
}

impl<B: SnarkBackend> PlanNode<B> {
    /// Returns the gadget associated with this plan node. Note that each plan node has exactly one gadget.
    fn gadget(&self) -> Arc<dyn IsGadgetNode<B>> {
        todo!()
    }

    /// Outputs the DataFrame resulting from executing this plan node.
    fn output(&self) -> HintDF {
        todo!()
    }
}

pub trait IsGadgetNode<B>: Any + Send + Sync
where
    B: SnarkBackend,
{
    /// Returns the children gadgets of this gadget. Note that the child of a gadget is a gadget, not a plan node.
    fn children(&self) -> Vec<Node<B>> {
        todo!()
    }
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
    fn ancestry(&self) -> GadgetAncestry;
}
pub trait IsLpNode<B>: Any + Send + Sync
where
    B: SnarkBackend,
{
    fn children(&self) -> Vec<Node<B>> {
        todo!()
    }
    /// Constructs a proof plan node from a DataFusion logical plan.
    // TODO: We might not need ctx here
    fn from_lp(_plan: LogicalPlan) -> Self
    where
        Self: Sized;

    fn lp(&self) -> LogicalPlan;
}

pub trait IsExprNode<B>: Any + Send + Sync
where
    B: SnarkBackend,
{
    fn children(&self) -> Vec<Node<B>> {
        todo!()
    }
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
