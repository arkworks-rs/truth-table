use std::{
    any::Any,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{Arc, Weak},
};

use arithmetic::IsTable;
use ark_piop::{SnarkBackend, errors::SnarkResult};
use arrow_schema::SchemaRef;
use datafusion_common::Statistics;
use datafusion_expr::{Expr, LogicalPlan};
use derivative::Derivative;
use indexmap::IndexMap;

use crate::{
    irs::nodes::{
        cost::ProvingCost,
        hints::HintDF,
        plan::{
            exprs::{binary_expr, column, literal},
            lps::{filter, projection, table_scan},
        },
    },
    irs::shared_ir::VirtualizedIr,
    prover::irs::{GadgetReadyIr, VirtualizedIr as ProverVirtualizedIr},
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
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
    Gadget(Arc<dyn IsProverGadgetNode<B>>),
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

pub trait NodeVirtualWitnessOps<B>: IsNode<B>
where
    B: SnarkBackend,
{
    fn add_virtual_witness<T>(
        &self,
        id: NodeId,
        virtualized_ir: &mut VirtualizedIr<B, T>,
    ) -> SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone;

    fn initialize_gadgets<T>(
        &self,
        id: NodeId,
        virtualized_ir: &mut VirtualizedIr<B, T>,
    ) -> SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone;
}

impl<B: SnarkBackend> NodeVirtualWitnessOps<B> for Node<B> {
    fn add_virtual_witness<T>(
        &self,
        id: NodeId,
        virtualized_ir: &mut VirtualizedIr<B, T>,
    ) -> SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone,
    {
        match &self {
            Node::Plan(plan_node) => plan_node.add_virtual_witness(id, virtualized_ir),
            Node::Gadget(_) => Ok(()),
        }
    }

    fn initialize_gadgets<T>(
        &self,
        id: NodeId,
        virtualized_ir: &mut VirtualizedIr<B, T>,
    ) -> SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone,
    {
        match &self {
            Node::Plan(plan_node) => plan_node.initialize_gadgets(id, virtualized_ir),
            Node::Gadget(gadget_node) => {
                let node_any = gadget_node.as_ref() as &dyn Any;
                if let Some(node) = node_any
                    .downcast_ref::<crate::irs::nodes::gadget::exprs::bin_eq::ProverNode<B>>()
                {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                if let Some(node) =
                    node_any.downcast_ref::<crate::irs::nodes::gadget::lps::filter::ProverNode<B>>()
                {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                if let Some(node) =
                    node_any.downcast_ref::<crate::irs::nodes::gadget::utils::eq::ProverNode<B>>()
                {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                if let Some(node) =
                    node_any.downcast_ref::<crate::irs::nodes::gadget::utils::neq::ProverNode<B>>()
                {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                Ok(())
            }
        }
    }
}

impl<B: SnarkBackend> NodeVirtualWitnessOps<B> for PlanNode<B> {
    fn add_virtual_witness<T>(
        &self,
        id: NodeId,
        virtualized_ir: &mut VirtualizedIr<B, T>,
    ) -> SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone,
    {
        match &self {
            PlanNode::LpBased(lp_node) => {
                let node_any = lp_node.as_ref() as &dyn Any;
                if let Some(node) = node_any.downcast_ref::<filter::FilterNode<B>>() {
                    return NodeVirtualWitnessOps::add_virtual_witness(node, id, virtualized_ir);
                }
                if let Some(node) = node_any.downcast_ref::<projection::ProverNode<B>>() {
                    return NodeVirtualWitnessOps::add_virtual_witness(node, id, virtualized_ir);
                }
                if let Some(node) = node_any.downcast_ref::<table_scan::ProverNode>() {
                    return NodeVirtualWitnessOps::add_virtual_witness(node, id, virtualized_ir);
                }
                Ok(())
            }
            PlanNode::ExprBased(expr_node) => {
                let node_any = expr_node.as_ref() as &dyn Any;
                if let Some(node) = node_any.downcast_ref::<column::ProverNode<B>>() {
                    return NodeVirtualWitnessOps::add_virtual_witness(node, id, virtualized_ir);
                }
                if let Some(node) = node_any.downcast_ref::<literal::ProverNode<B>>() {
                    return NodeVirtualWitnessOps::add_virtual_witness(node, id, virtualized_ir);
                }
                if let Some(node) = node_any.downcast_ref::<binary_expr::ProverNode<B>>() {
                    return NodeVirtualWitnessOps::add_virtual_witness(node, id, virtualized_ir);
                }
                Ok(())
            }
        }
    }

    fn initialize_gadgets<T>(
        &self,
        id: NodeId,
        virtualized_ir: &mut VirtualizedIr<B, T>,
    ) -> SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone,
    {
        match &self {
            PlanNode::LpBased(lp_node) => {
                let node_any = lp_node.as_ref() as &dyn Any;
                if let Some(node) = node_any.downcast_ref::<filter::FilterNode<B>>() {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                if let Some(node) = node_any.downcast_ref::<projection::ProverNode<B>>() {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                if let Some(node) = node_any.downcast_ref::<table_scan::ProverNode>() {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                Ok(())
            }
            PlanNode::ExprBased(expr_node) => {
                let node_any = expr_node.as_ref() as &dyn Any;
                if let Some(node) = node_any.downcast_ref::<column::ProverNode<B>>() {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                if let Some(node) = node_any.downcast_ref::<literal::ProverNode<B>>() {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                if let Some(node) = node_any.downcast_ref::<binary_expr::ProverNode<B>>() {
                    return NodeVirtualWitnessOps::initialize_gadgets(node, id, virtualized_ir);
                }
                Ok(())
            }
        }
    }
}

pub trait VerifierNodeOps<B>: IsNode<B>
where
    B: SnarkBackend,
{
    /// Optional hook for a pre-order gadget initialization pass.
    fn initialize_gadgets(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()>;
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
    /// Deterministic node identifier derived from the hashing strategy used by the IR.
    pub fn id(&self) -> NodeId {
        let mut hasher = DefaultHasher::new();
        std::ptr::hash(self, &mut hasher);
        hasher.finish()
    }
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
                let node = filter::FilterNode::from_lp(plan.clone(), weak_self.clone());
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
impl<B: SnarkBackend> VerifierNodeOps<B> for Node<B> {
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
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

impl<B: SnarkBackend> IsNode<B> for PlanNode<B> {
    fn name(&self) -> String {
        PlanNode::name(self)
    }

    fn display(&self) -> String {
        PlanNode::display(self)
    }

    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost {
        PlanNode::cost(self, statistics, schema)
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        PlanNode::children(self)
    }

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        PlanNode::child_edge_labels(self)
    }
}

pub trait IsProverGadgetNode<B>: IsNode<B>
where
    B: SnarkBackend,
{
    /// Runs the gadget prover
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()>;

    fn hints(&self) -> IndexMap<String, HintDF>;

    fn new() -> Self
    where
        Self: Sized;
}

pub trait IsVerifierGadgetNode<B>: IsNode<B>
where
    B: SnarkBackend,
{
    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut crate::verifier::irs::GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()>;
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
