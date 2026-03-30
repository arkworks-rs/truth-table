use crate::irs::nodes::{IsLpNode, IsNode, IsPlanNode, Node, PlanNode, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle, ACTIVATOR_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion_common::{DFSchemaRef, DataFusionError};
use datafusion_expr::{
    Expr, LogicalPlan,
    logical_plan::{Extension, UserDefinedLogicalNode},
};
use indexmap::IndexMap;
use std::any::Any;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::Arc;

pub struct LpNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
    gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "ResultCheck".to_string()
    }

    fn display(&self) -> String {
        format!("ResultCheck\nInput: {}", self.input.name())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.input.clone(), self.gadget.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(r_table)) =
            virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let Some(PayloadStructure::PlanPayload(t_table)) =
            virtualized_ir.payload_for_node(&self.input.id())
        else {
            return Ok(());
        };

        let aligned_t = project_prover_table_for_result_check(t_table, r_table)?;
        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            crate::irs::nodes::gadget::utils::result_check::INPUT_LABEL.to_string(),
            aligned_t,
        );
        gadget_payload.insert(
            crate::irs::nodes::gadget::utils::result_check::OUTPUT_LABEL.to_string(),
            r_table.clone(),
        );
        virtualized_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some((*self.gadget).clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("ResultCheck input cannot be a gadget node"),
        }
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("ResultCheck input cannot be a gadget node"),
        }
    }
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(plan: LogicalPlan, _self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let extension = match plan {
            LogicalPlan::Extension(extension) => extension,
            _ => panic!("Expected LogicalPlan::Extension for ResultCheck"),
        };
        let result_check = extension
            .node
            .as_any()
            .downcast_ref::<ResultCheckLogicalNode>()
            .expect("ResultCheck extension node");
        let input = crate::irs::tree::Tree::<B>::from_logical_plan(result_check.input())
            .root()
            .clone();
        Self::new(input)
    }

    fn lp(&self) -> LogicalPlan {
        let input_lp = match self.input.as_ref() {
            Node::Plan(PlanNode::LpBased(node)) => node.lp(),
            _ => panic!("ResultCheck input must be an LP node"),
        };
        wrap_logical_plan(input_lp)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(r_table)) =
            virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let Some(PayloadStructure::PlanPayload(t_table)) =
            virtualized_ir.payload_for_node(&self.input.id())
        else {
            return Ok(());
        };

        let aligned_t = project_verifier_table_for_result_check(t_table, r_table)?;
        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            crate::irs::nodes::gadget::utils::result_check::INPUT_LABEL.to_string(),
            aligned_t,
        );
        gadget_payload.insert(
            crate::irs::nodes::gadget::utils::result_check::OUTPUT_LABEL.to_string(),
            r_table.clone(),
        );
        virtualized_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> LpNode<B> {
    pub fn new(input: Arc<Node<B>>) -> Self {
        let gadget = Arc::new(Node::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::result_check::GadgetNode::<B>::new(),
        )));
        Self { input, gadget }
    }
}

fn project_prover_table_for_result_check<B: SnarkBackend>(
    input_t: &TrackedTable<B>,
    compact_r: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
    let compact_schema = compact_r
        .schema_ref()
        .expect("ResultCheck compact schema missing");
    let mut projected = IndexMap::new();
    for field in compact_schema.fields() {
        let poly = if field.name() == ACTIVATOR_COL_NAME {
            input_t
                .activator_tracked_poly()
                .expect("ResultCheck T activator missing")
        } else {
            input_t
                .tracked_polys_iter()
                .find_map(|(candidate, poly)| (candidate.name() == field.name()).then_some(poly.clone()))
                .unwrap_or_else(|| panic!("ResultCheck input column {} not found", field.name()))
        };
        projected.insert(field.clone(), poly);
    }
    Ok(TrackedTable::new(
        Some(compact_schema.clone()),
        projected,
        input_t.log_size(),
    ))
}

fn project_verifier_table_for_result_check<B: SnarkBackend>(
    input_t: &TrackedTableOracle<B>,
    compact_r: &TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
    let compact_schema = compact_r
        .schema_ref()
        .expect("ResultCheck compact schema missing");
    let mut projected = IndexMap::new();
    for field in compact_schema.fields() {
        let oracle = if field.name() == ACTIVATOR_COL_NAME {
            input_t
                .activator_tracked_poly()
                .expect("ResultCheck T activator missing")
        } else {
            input_t
                .tracked_oracles_iter()
                .find_map(|(candidate, oracle)| (candidate.name() == field.name()).then_some(oracle.clone()))
                .unwrap_or_else(|| panic!("ResultCheck input column {} not found", field.name()))
        };
        projected.insert(field.clone(), oracle);
    }
    Ok(TrackedTableOracle::new(
        Some(compact_schema.clone()),
        projected,
        input_t.log_size(),
    ))
}

#[derive(Debug, Clone)]
pub struct ResultCheckLogicalNode {
    input: Arc<LogicalPlan>,
    schema: DFSchemaRef,
}

impl ResultCheckLogicalNode {
    pub fn new(input: LogicalPlan) -> Self {
        let schema = input.schema().clone();
        Self {
            input: Arc::new(input),
            schema,
        }
    }

    pub fn input(&self) -> &LogicalPlan {
        self.input.as_ref()
    }

    fn key(&self) -> String {
        format!("{:?}", self.input)
    }
}

impl UserDefinedLogicalNode for ResultCheckLogicalNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "ResultCheck"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![self.input.as_ref()]
    }

    fn schema(&self) -> &DFSchemaRef {
        &self.schema
    }

    fn check_invariants(
        &self,
        _check: datafusion_expr::logical_plan::InvariantLevel,
        _plan: &LogicalPlan,
    ) -> datafusion_common::Result<()> {
        Ok(())
    }

    fn expressions(&self) -> Vec<Expr> {
        Vec::new()
    }

    fn fmt_for_explain(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ResultCheck")
    }

    fn with_exprs_and_inputs(
        &self,
        exprs: Vec<Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> datafusion_common::Result<Arc<dyn UserDefinedLogicalNode>> {
        if !exprs.is_empty() {
            return Err(DataFusionError::Plan(
                "ResultCheck does not accept expressions".to_string(),
            ));
        }
        if inputs.len() != 1 {
            return Err(DataFusionError::Plan(
                "ResultCheck expects a single input".to_string(),
            ));
        }
        Ok(Arc::new(ResultCheckLogicalNode::new(
            inputs.into_iter().next().unwrap(),
        )))
    }

    fn dyn_hash(&self, state: &mut dyn Hasher) {
        state.write(self.name().as_bytes());
        state.write(self.key().as_bytes());
    }

    fn dyn_eq(&self, other: &dyn UserDefinedLogicalNode) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .map(|o| self.key() == o.key())
            .unwrap_or(false)
    }

    fn dyn_ord(&self, other: &dyn UserDefinedLogicalNode) -> Option<Ordering> {
        let other_key = other.as_any().downcast_ref::<Self>()?.key();
        Some(self.key().cmp(&other_key))
    }
}

pub fn wrap_logical_plan(input: LogicalPlan) -> LogicalPlan {
    LogicalPlan::Extension(Extension {
        node: Arc::new(ResultCheckLogicalNode::new(input)),
    })
}

fn _result_check_key(plan: &LogicalPlan) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(format!("{plan:?}").as_bytes());
    hasher.finish()
}
