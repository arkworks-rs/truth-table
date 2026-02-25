use crate::irs::nodes::{
    IsLpNode, IsNode, IsPlanNode, Node, PlanNode, ProverNodeOps, VerifierNodeOps,
};
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD};
use ark_ff::BigInteger;
use ark_piop::SnarkBackend;
use ark_std::One;

use datafusion::arrow::datatypes::Schema;
use datafusion::prelude::DataFrame;
use datafusion_common::{DFSchemaRef, DataFusionError};
use datafusion_expr::{
    Expr, LogicalPlan, col, lit,
    logical_plan::{Extension, UserDefinedLogicalNode},
};
use indexmap::IndexMap;
use std::any::Any;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::Arc;

const REMAT_CONTIG_S_PREFIX: &str = "remat_contig_s";

pub struct LpNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "Rematerialize".to_string()
    }

    fn display(&self) -> String {
        format!("Rematerialize\nInput: {}", self.input.name())
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
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(crate::irs::payloads::PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };
        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                crate::irs::payloads::PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let Some(input_act) = input_table.activator_tracked_poly() else {
            return Ok(());
        };
        let s = input_act
            .evaluations()
            .into_iter()
            .filter(|val| *val == B::F::one())
            .count();

        let tracker_rc = input_act.tracker();
        let contig = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(current_table.log_size(), s)?;

        let mut polys = current_table.tracked_polys();
        polys.insert(ACTIVATOR_FIELD.clone(), contig);
        let schema = current_table.schema_ref().map(|schema| {
            let mut fields: Vec<_> = schema.fields().iter().cloned().collect();
            fields.push(ACTIVATOR_FIELD.as_ref().clone().into());
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });
        let updated = arithmetic::table::TrackedTable::new(schema, polys, current_table.log_size());
        virtualized_ir.set_payload_for_node(
            id,
            Some(crate::irs::payloads::PayloadStructure::PlanPayload(updated)),
        );

        let key = format!("{REMAT_CONTIG_S_PREFIX}_{}", remat_key(&self.input));
        tracker_rc
            .borrow_mut()
            .insert_miscellaneous_field(key, B::F::from(s as u64));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Rematerialize input cannot be a gadget node"),
        };

        let output_df = build_output_dataframe(input_hint_df.data_frame().clone());
        let should_materialize = output_df
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let materialize = field.name() != ACTIVATOR_COL_NAME;
                (field.clone(), materialize)
            })
            .collect::<IndexMap<_, _>>();
        crate::irs::nodes::hints::HintDF::new(output_df, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(_plan: LogicalPlan, _self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let extension = match _plan {
            LogicalPlan::Extension(extension) => extension,
            _ => panic!("Expected LogicalPlan::Extension for Rematerialize"),
        };
        let remat = extension
            .node
            .as_any()
            .downcast_ref::<RematerializeLogicalNode>()
            .expect("Rematerialize extension node");
        let input = crate::irs::tree::Tree::<B>::from_logical_plan(remat.input())
            .root()
            .clone();
        Self::new(input)
    }

    fn lp(&self) -> LogicalPlan {
        let input_lp = match self.input.as_ref() {
            Node::Plan(PlanNode::LpBased(node)) => node.lp(),
            _ => panic!("Rematerialize input must be an LP node"),
        };
        wrap_logical_plan(input_lp)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(crate::irs::payloads::PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };
        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                crate::irs::payloads::PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let Some(input_act) = input_table.activator_tracked_poly() else {
            return Ok(());
        };
        let tracker_rc = input_act.tracker();
        let key = format!("{REMAT_CONTIG_S_PREFIX}_{}", remat_key(&self.input));
        let s_field = tracker_rc.borrow().miscellaneous_field_element(&key)?;
        let s = field_to_usize::<B::F>(s_field)?;

        let contig = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_oracle(current_table.log_size(), s)?;

        let mut oracles = current_table.tracked_oracles();
        oracles.insert(ACTIVATOR_FIELD.clone(), contig);
        let schema = current_table.schema_ref().map(|schema| {
            let mut fields: Vec<_> = schema.fields().iter().cloned().collect();
            fields.push(ACTIVATOR_FIELD.as_ref().clone().into());
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });
        let updated = arithmetic::table_oracle::TrackedTableOracle::new(
            schema,
            oracles,
            current_table.log_size(),
        );
        virtualized_ir.set_payload_for_node(
            id,
            Some(crate::irs::payloads::PayloadStructure::PlanPayload(updated)),
        );
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> LpNode<B> {
    pub fn new(input: Arc<Node<B>>) -> Self {
        Self { input }
    }
}

/// A logical plan node that indicates that its input should be rematerialized.
/// On the logical plan level, this node behaves like an identity operation.
#[derive(Debug, Clone)]
pub struct RematerializeLogicalNode {
    input: Arc<LogicalPlan>,
    schema: DFSchemaRef,
}

impl RematerializeLogicalNode {
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

impl UserDefinedLogicalNode for RematerializeLogicalNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "Rematerialize"
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
        write!(f, "Rematerialize")
    }

    fn with_exprs_and_inputs(
        &self,
        exprs: Vec<Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> datafusion_common::Result<Arc<dyn UserDefinedLogicalNode>> {
        if !exprs.is_empty() {
            return Err(DataFusionError::Plan(
                "Rematerialize does not accept expressions".to_string(),
            ));
        }
        if inputs.len() != 1 {
            return Err(DataFusionError::Plan(
                "Rematerialize expects a single input".to_string(),
            ));
        }
        Ok(Arc::new(RematerializeLogicalNode::new(
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
        node: Arc::new(RematerializeLogicalNode::new(input)),
    })
}

fn build_output_dataframe(input: DataFrame) -> DataFrame {
    // input
    let has_activator = input
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    if !has_activator {
        return crate::irs::nodes::hints::sort_by_row_id_if_present(input)
            .expect("rematerialize output sort should succeed");
    }
    let filtered = input
        .filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))
        .expect("rematerialize activator filter should succeed");
    crate::irs::nodes::hints::sort_by_row_id_if_present(filtered)
        .expect("rematerialize output sort should succeed")
}

fn remat_key<B: SnarkBackend>(input: &Node<B>) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(input.display().as_bytes());
    hasher.finish()
}

fn field_to_usize<F: ark_ff::PrimeField>(value: F) -> ark_piop::errors::SnarkResult<usize> {
    let big = value.into_bigint();
    let bytes = big.to_bytes_le();
    let mut out: usize = 0;
    let max = std::mem::size_of::<usize>();
    for (i, byte) in bytes.iter().enumerate() {
        if i >= max {
            if *byte != 0u8 {
                return Err(ark_piop::errors::SnarkError::VerifierError(
                    ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(
                        "rematerialize contig s does not fit into usize".to_string(),
                    ),
                ));
            }
            continue;
        }
        out |= (*byte as usize) << (8 * i);
    }
    Ok(out)
}
