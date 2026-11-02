//! An empty table, proved empty by a subtree whose output has no rows.
//!
//! The node proves its `witness` subtree as usual and zerochecks the
//! witness's output activator. Its own output has the node's schema and the
//! public all-zero activator: the data columns are committed like any other
//! node's, but no row of them is active. The planner replaces the operators
//! above a witness that only pass on emptiness (filters, projections, inner
//! joins, ...) by one such node, so they are never proved.

use crate::irs::nodes::{
    IsLpNode, IsNode, IsPlanNode, Node, PlanNode, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;
use crate::session::session_context;
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use ark_piop::errors::SnarkError;
use ark_piop::verifier::errors::VerifierError;
use ark_std::Zero;
use datafusion::arrow::datatypes::Schema;
use datafusion::prelude::DataFrame;
use datafusion_common::{DFSchemaRef, DataFusionError};
use datafusion_expr::{
    Expr, LogicalPlan, lit,
    logical_plan::{EmptyRelation, Extension, UserDefinedLogicalNode},
};
use indexmap::IndexMap;
use std::any::Any;
use std::cmp::Ordering;
use std::hash::Hasher;
use std::sync::Arc;

pub struct LpNode<B: SnarkBackend> {
    witness: Arc<Node<B>>,
    plan: ProvedEmptyLogicalNode,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "ProvedEmpty".to_string()
    }

    fn display(&self) -> String {
        format!("ProvedEmpty\nWitness: {}", self.witness.name())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.witness.clone()]
    }
}

impl<B: SnarkBackend> LpNode<B> {
    /// The node's output: no rows, so materialization pads it to one
    /// inactive row. The activator stays virtual; `add_virtual_witness`
    /// sets it to zero.
    fn output_hint(&self) -> crate::irs::nodes::hints::HintDF {
        let ctx =
            crate::irs::nodes::hints::scoped_schema_only_ctx().unwrap_or_else(session_context);
        let df = DataFrame::new(
            ctx.state(),
            LogicalPlan::EmptyRelation(EmptyRelation {
                produce_one_row: false,
                schema: self.plan.schema.clone(),
            }),
        )
        .with_column(ACTIVATOR_COL_NAME, lit(false))
        .expect("an empty relation takes an activator column");
        let should_materialize = df
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let materialize =
                    field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), materialize)
            })
            .collect::<IndexMap<_, _>>();
        crate::irs::nodes::hints::HintDF::new(df, should_materialize)
    }
}

fn with_zero_activator_field(schema: Option<&Schema>) -> Option<Schema> {
    schema.map(|schema| {
        let mut fields: Vec<_> = schema.fields().iter().cloned().collect();
        fields.push(ACTIVATOR_FIELD.clone());
        Schema::new_with_metadata(fields, schema.metadata().clone())
    })
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(witness)) =
            virtualized_ir.payload_for_node(&self.witness.id())
        else {
            return Ok(());
        };
        let tracker = witness_activator_prover(witness)?.tracker();
        let current = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => Default::default(),
        };
        let zero = tracker
            .borrow_mut()
            .get_or_build_contig_one_poly(current.log_size(), 0)?;
        let mut polys = current.tracked_polys();
        polys.insert(ACTIVATOR_FIELD.clone(), zero);
        let table = arithmetic::table::TrackedTable::new_with_side_cols(
            with_zero_activator_field(current.schema_ref()),
            polys,
            current.log_size(),
            current.side_cols(),
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(witness)) =
            virtualized_ir.payload_for_node(&self.witness.id())
        else {
            return Ok(());
        };
        let activator = witness_activator_prover(witness)?;
        match activator.as_constant() {
            Some(value) if value.is_zero() => Ok(()),
            Some(_) => Err(false_claim()),
            None => prover.add_mv_zerocheck_claim(activator.id()),
        }
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(witness)) =
            virtualized_ir.payload_for_node(&self.witness.id())
        else {
            return Ok(());
        };
        let tracker = witness_activator_verifier(witness)?.tracker();
        let current = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => Default::default(),
        };
        let zero = tracker
            .borrow_mut()
            .get_or_build_contig_one_poly(current.log_size(), 0)?;
        let mut oracles = current.tracked_oracles();
        oracles.insert(ACTIVATOR_FIELD.clone(), zero);
        let table = arithmetic::table_oracle::TrackedTableOracle::new_with_side_cols(
            with_zero_activator_field(current.schema_ref()),
            oracles,
            current.log_size(),
            current.side_cols(),
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(witness)) =
            virtualized_ir.payload_for_node(&self.witness.id())
        else {
            return Ok(());
        };
        let activator = witness_activator_verifier(witness)?;
        match activator.as_constant() {
            Some(value) if value.is_zero() => {}
            Some(_) => return Err(not_empty()),
            None => verifier.add_mv_zerocheck_claim(activator.id()),
        }
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

fn false_claim() -> SnarkError {
    SnarkError::ProverError(ark_piop::prover::errors::ProverError::HonestProverError(
        ark_piop::prover::errors::HonestProverError::FalseClaim,
    ))
}

fn not_empty() -> SnarkError {
    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(
        "the witness of an empty table has active rows".to_string(),
    ))
}

/// A table without an activator has every row active, so it cannot be empty.
fn witness_activator_prover<B: SnarkBackend>(
    witness: &arithmetic::table::TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<ark_piop::prover::structs::polynomial::TrackedPoly<B>> {
    witness.activator_tracked_poly().ok_or_else(false_claim)
}

fn witness_activator_verifier<B: SnarkBackend>(
    witness: &arithmetic::table_oracle::TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<ark_piop::verifier::structs::oracle::TrackedOracle<B>> {
    witness.activator_tracked_poly().ok_or_else(not_empty)
}

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        self.output_hint()
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        self.output_hint()
    }
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(plan: LogicalPlan, _self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let LogicalPlan::Extension(extension) = plan else {
            panic!("Expected LogicalPlan::Extension for ProvedEmpty");
        };
        let plan = extension
            .node
            .as_any()
            .downcast_ref::<ProvedEmptyLogicalNode>()
            .expect("ProvedEmpty extension node")
            .clone();
        let witness = crate::irs::tree::Tree::<B>::from_logical_plan(plan.witness())
            .root()
            .clone();
        Self { witness, plan }
    }

    fn lp(&self) -> LogicalPlan {
        let witness = match self.witness.as_ref() {
            Node::Plan(PlanNode::LpBased(node)) => node.lp(),
            _ => panic!("ProvedEmpty witness must be an LP node"),
        };
        LogicalPlan::Extension(Extension {
            node: Arc::new(ProvedEmptyLogicalNode::new(
                witness,
                self.plan.schema.clone(),
            )),
        })
    }
}

/// An empty table with `schema`, whose emptiness `witness` proves.
#[derive(Debug, Clone)]
pub struct ProvedEmptyLogicalNode {
    witness: Arc<LogicalPlan>,
    schema: DFSchemaRef,
}

impl ProvedEmptyLogicalNode {
    pub fn new(witness: LogicalPlan, schema: DFSchemaRef) -> Self {
        Self {
            witness: Arc::new(witness),
            schema,
        }
    }

    pub fn witness(&self) -> &LogicalPlan {
        self.witness.as_ref()
    }

    fn key(&self) -> String {
        format!("{:?}{:?}", self.witness, self.schema)
    }
}

impl UserDefinedLogicalNode for ProvedEmptyLogicalNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "ProvedEmpty"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![self.witness.as_ref()]
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
        write!(f, "ProvedEmpty")
    }

    fn with_exprs_and_inputs(
        &self,
        exprs: Vec<Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> datafusion_common::Result<Arc<dyn UserDefinedLogicalNode>> {
        if !exprs.is_empty() || inputs.len() != 1 {
            return Err(DataFusionError::Plan(
                "ProvedEmpty takes one input and no expressions".to_string(),
            ));
        }
        let witness = inputs.into_iter().next().unwrap();
        Ok(Arc::new(Self::new(witness, self.schema.clone())))
    }

    fn dyn_hash(&self, state: &mut dyn Hasher) {
        state.write(self.name().as_bytes());
        state.write(self.key().as_bytes());
    }

    fn dyn_eq(&self, other: &dyn UserDefinedLogicalNode) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.key() == other.key())
    }

    fn dyn_ord(&self, other: &dyn UserDefinedLogicalNode) -> Option<Ordering> {
        let other_key = other.as_any().downcast_ref::<Self>()?.key();
        Some(self.key().cmp(&other_key))
    }
}

/// An empty table with `schema` whose emptiness `witness` proves.
pub fn proved_empty(witness: LogicalPlan, schema: DFSchemaRef) -> LogicalPlan {
    LogicalPlan::Extension(Extension {
        node: Arc::new(ProvedEmptyLogicalNode::new(witness, schema)),
    })
}
