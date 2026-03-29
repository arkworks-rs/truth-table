use crate::irs::nodes::{IsLpNode, IsNode, IsPlanNode, Node, PlanNode, ProverNodeOps, VerifierNodeOps};
use ark_ff::Zero;
use ark_piop::SnarkBackend;
use datafusion_common::{DFSchemaRef, DataFusionError};
use datafusion_expr::{
    Expr, LogicalPlan,
    logical_plan::{Extension, UserDefinedLogicalNode},
};
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
        vec![self.input.clone()]
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
        prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(crate::irs::payloads::PayloadStructure::PlanPayload(r_table)) =
            virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let Some(crate::irs::payloads::PayloadStructure::PlanPayload(t_table)) =
            virtualized_ir.payload_for_node(&self.input.id())
        else {
            return Ok(());
        };

        prove_result_check(prover, t_table, r_table)?;
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
        None
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
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(crate::irs::payloads::PayloadStructure::PlanPayload(r_table)) =
            virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let Some(crate::irs::payloads::PayloadStructure::PlanPayload(t_table)) =
            virtualized_ir.payload_for_node(&self.input.id())
        else {
            return Ok(());
        };

        verify_result_check(verifier, t_table, r_table)?;
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
        Self { input }
    }
}

fn prove_result_check<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    t_table: &arithmetic::table::TrackedTable<B>,
    r_table: &arithmetic::table::TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let t_activator = t_table
        .activator_tracked_poly()
        .expect("ResultCheck expects T to have an activator");
    let r_activator = r_table
        .activator_tracked_poly()
        .expect("ResultCheck expects R to have an activator");

    #[cfg(feature = "honest-prover")]
    {
        let t_act = t_activator.evaluations();
        let r_act = r_activator.evaluations();
        if t_act != r_act {
            let mismatches = t_act
                .iter()
                .zip(r_act.iter())
                .enumerate()
                .filter_map(|(idx, (t, r))| (t != r).then_some(idx))
                .take(8)
                .collect::<Vec<_>>();
            tracing::error!(
                t_rows = t_act.len(),
                r_rows = r_act.len(),
                ?mismatches,
                "ResultCheck activator mismatch"
            );
        }
    }

    prover.add_mv_zerocheck_claim((&t_activator - &r_activator).id())?;

    let num_data_cols = t_table.num_data_tracked_cols();
    debug_assert_eq!(
        num_data_cols,
        r_table.num_data_tracked_cols(),
        "ResultCheck expects T and R to have the same number of data columns",
    );

    if num_data_cols == 0 {
        return Ok(());
    }

    let mut challenges = Vec::with_capacity(num_data_cols);
    for _ in 0..num_data_cols {
        challenges.push(prover.get_and_append_challenge(b"result_check_fold")?);
    }
    let t_fold = t_table.fold_all_data_columns(&challenges);
    let r_fold = r_table.fold_all_data_columns(&challenges);

    #[cfg(feature = "honest-prover")]
    {
        let t_fold_evals = t_fold.data_tracked_poly().evaluations();
        let r_fold_evals = r_fold.data_tracked_poly().evaluations();
        let t_act = t_activator.evaluations();
        let mismatches = t_fold_evals
            .iter()
            .zip(r_fold_evals.iter())
            .zip(t_act.iter())
            .enumerate()
            .filter_map(|(idx, ((t, r), a))| ((*a != B::F::zero()) && (t != r)).then_some(idx))
            .take(8)
            .collect::<Vec<_>>();
        if !mismatches.is_empty() {
            tracing::error!(
                ?mismatches,
                t_schema = ?t_table.schema(),
                r_schema = ?r_table.schema(),
                "ResultCheck folded-data mismatch on active rows"
            );
        }
    }

    let zero_poly =
        &(&t_fold.data_tracked_poly() - &r_fold.data_tracked_poly()) * &t_activator;
    prover.add_mv_zerocheck_claim(zero_poly.id())?;
    Ok(())
}

fn verify_result_check<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    t_table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    r_table: &arithmetic::table_oracle::TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let t_activator = t_table
        .activator_tracked_poly()
        .expect("ResultCheck expects T to have an activator");
    let r_activator = r_table
        .activator_tracked_poly()
        .expect("ResultCheck expects R to have an activator");

    verifier.add_zerocheck_claim((&t_activator - &r_activator).id());

    let num_data_cols = t_table.num_data_tracked_col_oracles();
    debug_assert_eq!(
        num_data_cols,
        r_table.num_data_tracked_col_oracles(),
        "ResultCheck expects T and R to have the same number of data columns",
    );

    if num_data_cols == 0 {
        return Ok(());
    }

    let mut challenges = Vec::with_capacity(num_data_cols);
    for _ in 0..num_data_cols {
        challenges.push(verifier.get_and_append_challenge(b"result_check_fold")?);
    }
    let t_fold = t_table.fold_all_data_oracles(&challenges);
    let r_fold = r_table.fold_all_data_oracles(&challenges);
    let zero_oracle =
        &(&t_fold.data_tracked_oracle() - &r_fold.data_tracked_oracle()) * &t_activator;
    verifier.add_zerocheck_claim(zero_oracle.id());
    Ok(())
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
