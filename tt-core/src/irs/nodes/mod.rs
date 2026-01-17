use std::{
    any::Any,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{Arc, Weak},
};

use crate::{
    irs::nodes::{
        cost::ProvingCost,
        hints::HintDF,
        plan::{
            exprs::{
                aggregate_function, alias, between, binary_expr, cast, column, in_list, literal,
            },
            lps::{aggregate, filter, join, limit, projection, sort, subquery_alias, table_scan},
        },
    },
    prover::irs::{GadgetReadyIr as ProverGadgetReadyIr, VirtualizedIr as ProverVirtualizedIr},
    verifier::irs::{
        GadgetReadyIr as VerifierGadgetReadyIr, VirtualizedIr as VerifierVirtualizedIr,
    },
};
use ark_piop::{SnarkBackend, errors::SnarkResult};
use arrow_schema::SchemaRef;
use datafusion_common::Statistics;
use datafusion_expr::{Expr, LogicalPlan, builder::subquery_alias, in_subquery};
use derivative::Derivative;
use indexmap::IndexMap;
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
    fn display(&self) -> String;
    /// Estimates the proving cost of this node given statistics and schema.
    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;
    /// Optional hook for pre-order gadget planning.
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()>;
    /// Returns this node's children.
    fn children(&self) -> Vec<Arc<Node<B>>>;
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }
}

pub(crate) fn display_with_inputs<B: SnarkBackend>(name: &str, inputs: &[Arc<Node<B>>]) -> String {
    if inputs.is_empty() {
        return name.to_string();
    }
    let input_names: Vec<String> = inputs.iter().map(|node| node.name()).collect();
    format!("{name}\nInputs: {}", input_names.join(", "))
}

pub trait ProverNodeOps<B>: IsNode<B>
where
    B: SnarkBackend,
{
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()>;

    /// Optional hook for a pre-order gadget initialization pass.
    fn initialize_gadgets(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()>;
}

pub trait VerifierNodeOps<B>: IsNode<B>
where
    B: SnarkBackend,
{
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()>;

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
    /// Returns the gadget associated with this plan node, if any.
    fn gadget(&self) -> Option<Node<B>>;
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
            LogicalPlan::Aggregate(_) => Arc::new_cyclic(|weak_self| {
                let node = aggregate::ProverAggregateNode::from_lp(plan.clone(), weak_self.clone());
                Node::Plan(PlanNode::LpBased(Arc::new(node)))
            }),
            LogicalPlan::Sort(_) => Arc::new_cyclic(|weak_self| {
                let node = sort::GadgetNode::from_lp(plan.clone(), weak_self.clone());
                Node::Plan(PlanNode::LpBased(Arc::new(node)))
            }),
            LogicalPlan::Join(_) => Arc::new_cyclic(|weak_self| {
                let node = join::JoinNode::from_lp(plan.clone(), weak_self.clone());
                Node::Plan(PlanNode::LpBased(Arc::new(node)))
            }),
            LogicalPlan::SubqueryAlias(_) => Arc::new_cyclic(|weak_self| {
                let node =
                    subquery_alias::SubqueryAliasNode::from_lp(plan.clone(), weak_self.clone());
                Node::Plan(PlanNode::LpBased(Arc::new(node)))
            }),
            LogicalPlan::Limit(_) => Arc::new_cyclic(|weak_self| {
                let node = limit::LimitNode::from_lp(plan.clone(), weak_self.clone());
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
                let node = binary_expr::BinaryExprNode::from_expr(
                    expr.clone(),
                    weak_self.clone(),
                    parent.clone(),
                    scope.clone(),
                );
                Node::Plan(PlanNode::ExprBased(Arc::new(node)))
            }),
            Expr::Cast(_) => Arc::new_cyclic(|weak_self| {
                let node = cast::ProverNode::from_expr(
                    expr.clone(),
                    weak_self.clone(),
                    parent.clone(),
                    scope.clone(),
                );
                Node::Plan(PlanNode::ExprBased(Arc::new(node)))
            }),
            Expr::Alias(_) => Arc::new_cyclic(|weak_self| {
                let node = alias::ProverNode::from_expr(
                    expr.clone(),
                    weak_self.clone(),
                    parent.clone(),
                    scope.clone(),
                );
                Node::Plan(PlanNode::ExprBased(Arc::new(node)))
            }),
            Expr::AggregateFunction(_) => Arc::new_cyclic(|weak_self| {
                let node = aggregate_function::ProverNode::from_expr(
                    expr.clone(),
                    weak_self.clone(),
                    parent.clone(),
                    scope.clone(),
                );
                Node::Plan(PlanNode::ExprBased(Arc::new(node)))
            }),
            Expr::Between(_) => Arc::new_cyclic(|weak_self| {
                let node = between::ProverNode::from_expr(
                    expr.clone(),
                    weak_self.clone(),
                    parent.clone(),
                    scope.clone(),
                );
                Node::Plan(PlanNode::ExprBased(Arc::new(node)))
            }),
            Expr::InList(_) => Arc::new_cyclic(|weak_self| {
                let node = in_list::ProverNode::from_expr(
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
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            Node::Plan(plan_node) => plan_node.initialize_gadget_plans(id, planned_ir),
            Node::Gadget(gadget_node) => gadget_node.initialize_gadget_plans(id, planned_ir),
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

impl<B: SnarkBackend> ProverNodeOps<B> for Node<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            Node::Plan(plan_node) => {
                ProverNodeOps::add_virtual_witness(plan_node, id, virtualized_ir)
            }
            Node::Gadget(gadget_node) => {
                ProverNodeOps::add_virtual_witness(gadget_node.as_ref(), id, virtualized_ir)
            }
        }
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            Node::Plan(plan_node) => {
                ProverNodeOps::initialize_gadgets(plan_node, id, virtualized_ir)
            }
            Node::Gadget(gadget_node) => {
                ProverNodeOps::initialize_gadgets(gadget_node.as_ref(), id, virtualized_ir)
            }
        }
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for Node<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            Node::Plan(plan_node) => {
                VerifierNodeOps::add_virtual_witness(plan_node, id, virtualized_ir)
            }
            Node::Gadget(gadget_node) => {
                VerifierNodeOps::add_virtual_witness(gadget_node.as_ref(), id, virtualized_ir)
            }
        }
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            Node::Plan(plan_node) => {
                VerifierNodeOps::initialize_gadgets(plan_node, id, virtualized_ir)
            }
            Node::Gadget(gadget_node) => {
                VerifierNodeOps::initialize_gadgets(gadget_node.as_ref(), id, virtualized_ir)
            }
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

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            PlanNode::LpBased(lp_node) => lp_node.initialize_gadget_plans(id, planned_ir),
            PlanNode::ExprBased(expr_node) => expr_node.initialize_gadget_plans(id, planned_ir),
        }
    }

    /// Returns the gadget associated with this plan node, if any.
    fn gadget(&self) -> Option<Node<B>> {
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

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        PlanNode::initialize_gadget_plans(self, id, planned_ir)
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        PlanNode::children(self)
    }

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        PlanNode::child_edge_labels(self)
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for PlanNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            PlanNode::LpBased(lp_node) => {
                ProverNodeOps::add_virtual_witness(lp_node.as_ref(), id, virtualized_ir)
            }
            PlanNode::ExprBased(expr_node) => {
                ProverNodeOps::add_virtual_witness(expr_node.as_ref(), id, virtualized_ir)
            }
        }
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            PlanNode::LpBased(lp_node) => {
                ProverNodeOps::initialize_gadgets(lp_node.as_ref(), id, virtualized_ir)
            }
            PlanNode::ExprBased(expr_node) => {
                ProverNodeOps::initialize_gadgets(expr_node.as_ref(), id, virtualized_ir)
            }
        }
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for PlanNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            PlanNode::LpBased(lp_node) => {
                VerifierNodeOps::add_virtual_witness(lp_node.as_ref(), id, virtualized_ir)
            }
            PlanNode::ExprBased(expr_node) => {
                VerifierNodeOps::add_virtual_witness(expr_node.as_ref(), id, virtualized_ir)
            }
        }
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        match &self {
            PlanNode::LpBased(lp_node) => {
                VerifierNodeOps::initialize_gadgets(lp_node.as_ref(), id, virtualized_ir)
            }
            PlanNode::ExprBased(expr_node) => {
                VerifierNodeOps::initialize_gadgets(expr_node.as_ref(), id, virtualized_ir)
            }
        }
    }
}

pub trait IsGadgetNode<B>: IsNode<B> + ProverNodeOps<B> + VerifierNodeOps<B>
where
    B: SnarkBackend,
{
    /// Runs the gadget prover
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut ProverGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()>;
    /// Runs the gadget honest prover check.
    ///
    /// Defaults to `prove` so existing gadgets don't need to implement it
    /// unless they want a cheaper check-only path.
    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut ProverGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()>;
    /// Runs the gadget verifier
    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()>;
    fn hints(&self) -> IndexMap<String, HintDF>;
}
pub trait IsLpNode<B>: IsPlanNode<B> + ProverNodeOps<B> + VerifierNodeOps<B>
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

pub trait IsExprNode<B>: IsPlanNode<B> + ProverNodeOps<B> + VerifierNodeOps<B>
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
