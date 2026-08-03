use crate::irs::nodes::{
    IsLpNode, IsNode, IsPlanNode, Node, PlanNode, ProverNodeOps, VerifierNodeOps,
    utils::remat as remat_gadget,
};
use crate::irs::payloads::PayloadStructure;
use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::BigInteger;
use ark_piop::SnarkBackend;
use ark_std::One;

use datafusion::arrow::datatypes::{Field, Schema};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::{Column, DFSchemaRef, DataFusionError, Result as DataFusionResult};
use datafusion_expr::{
    BinaryExpr, Expr, ExprFunctionExt, LogicalPlan, Operator, col, lit,
    logical_plan::{Extension, UserDefinedLogicalNode},
};
use indexmap::IndexMap;
use std::any::Any;
use std::cmp::Ordering;
use std::hash::Hasher;
use std::sync::Arc;

const REMAT_CONTIG_S_PREFIX: &str = "remat_contig_s";

pub struct LpNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
    // The gadget node for proving the rematerialize (compaction) operation:
    // it asserts that the output table is a permutation of the input's active
    // rows (see TruthTable paper §6.4 "Compaction" / PIOP 13).
    gadget: Arc<Node<B>>,
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
        vec![self.input.clone(), self.gadget.clone()]
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

        let key = remat_contig_key(virtualized_ir.tree(), id);
        tracker_rc
            .borrow_mut()
            .insert_miscellaneous_field(key, B::F::from(s as u64));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(strip_row_id_tracked_table(table)),
            _ => None,
        };
        let output_table =
            virtualized_ir
                .payload_for_node(&id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(strip_row_id_tracked_table(table)),
                    _ => None,
                });

        let (Some(input), Some(output)) = (input_table, output_table) else {
            return Ok(());
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(remat_gadget::INPUT_LABEL.to_string(), input);
        gadget_payload.insert(remat_gadget::OUTPUT_LABEL.to_string(), output);
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
        Some(self.gadget.as_ref().clone())
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
                // __row_id__ stays virtual: oracle files strip it via
                // `SELECT * EXCEPT (__row_id__)`, so it never reaches the
                // verifier's TableSource schema.
                let materialize =
                    field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), materialize)
            })
            .collect::<IndexMap<_, _>>();
        crate::irs::nodes::hints::HintDF::new(output_df, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Rematerialize input cannot be a gadget node"),
        };

        // Verifier planning only needs schema; rematerialize does not change schema.
        let output_df = input_hint_df.data_frame().clone();
        let should_materialize = output_df
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let materialize =
                    field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), materialize)
            })
            .collect::<IndexMap<_, _>>();
        crate::irs::nodes::hints::HintDF::new(output_df, should_materialize)
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
        let key = remat_contig_key(virtualized_ir.tree(), id);
        let s_field = tracker_rc.borrow().miscellaneous_field_element(&key)?;
        let s = field_to_usize::<B::F>(s_field)?;

        let contig = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(current_table.log_size(), s)?;

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
        id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(strip_row_id_tracked_oracle(table)),
            _ => None,
        };
        let output_table =
            virtualized_ir
                .payload_for_node(&id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(strip_row_id_tracked_oracle(table)),
                    _ => None,
                });

        let (Some(input), Some(output)) = (input_table, output_table) else {
            return Ok(());
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(remat_gadget::INPUT_LABEL.to_string(), input);
        gadget_payload.insert(remat_gadget::OUTPUT_LABEL.to_string(), output);
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
        // `contigous: true` — the output activator is a deterministic
        // contig-one poly of weight s, so no separate contiguity check is
        // needed beyond what the wrapped remat gadget provides.
        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            remat_gadget::GadgetNode::new(true),
        )));
        Self { input, gadget }
    }
}

fn strip_row_id_tracked_table<B: SnarkBackend>(table: &TrackedTable<B>) -> TrackedTable<B> {
    let Some(schema) = table.schema_ref() else {
        return table.clone();
    };
    if !schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        return table.clone();
    }
    let mut cols = IndexMap::new();
    for (field, poly) in table.tracked_polys_iter() {
        if field.name() != ROW_ID_COL_NAME {
            cols.insert(field.clone(), poly.clone());
        }
    }
    let fields: Vec<Field> = cols.keys().map(|field| field.as_ref().clone()).collect();
    let schema = Some(Schema::new_with_metadata(fields, schema.metadata().clone()));
    TrackedTable::new(schema, cols, table.log_size())
}

fn strip_row_id_tracked_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let Some(schema) = table.schema_ref() else {
        return table.clone();
    };
    if !schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        return table.clone();
    }
    let mut cols = IndexMap::new();
    for (field, oracle) in table.tracked_oracles_iter() {
        if field.name() != ROW_ID_COL_NAME {
            cols.insert(field.clone(), oracle.clone());
        }
    }
    let fields: Vec<Field> = cols.keys().map(|field| field.as_ref().clone()).collect();
    let schema = Some(Schema::new_with_metadata(fields, schema.metadata().clone()));
    TrackedTableOracle::new(schema, cols, table.log_size())
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
    let has_activator = input
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    let filtered = if has_activator {
        input
            .filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))
            .expect("rematerialize activator filter should succeed")
    } else {
        input
    };
    let sorted = crate::irs::nodes::hints::sort_by_row_id_if_present(filtered)
        .expect("rematerialize output sort should succeed");
    reassign_row_id_to_natural_indices(sorted)
        .expect("rematerialize row_id reassignment should succeed")
}

fn reassign_row_id_to_natural_indices(df: DataFrame) -> DataFusionResult<DataFrame> {
    let row_id_expr = df.schema().iter().find_map(|(qualifier, field)| {
        (field.name() == ROW_ID_COL_NAME)
            .then(|| Expr::Column(Column::new(qualifier.cloned(), field.name())))
    });
    let Some(row_id_expr) = row_id_expr else {
        return Ok(df);
    };
    let row_number_minus_one = Expr::BinaryExpr(BinaryExpr::new(
        Box::new(
            row_number()
                .partition_by(Vec::new())
                .order_by(vec![row_id_expr.sort(true, true)])
                .build()?,
        ),
        Operator::Minus,
        Box::new(lit(1_i64)),
    ))
    .alias(ROW_ID_COL_NAME);
    let mut projection: Vec<Expr> = df
        .schema()
        .iter()
        .filter(|(_, field)| field.name() != ROW_ID_COL_NAME)
        .map(|(qualifier, field)| Expr::Column(Column::new(qualifier.cloned(), field.name())))
        .collect();
    projection.push(row_number_minus_one);
    df.select(projection)
}

fn remat_contig_key<B: SnarkBackend>(
    tree: &crate::irs::tree::Tree<B>,
    id: crate::irs::nodes::NodeId,
) -> String {
    let path = structural_path_to_node(tree, id)
        .unwrap_or_else(|| panic!("Rematerialize could not derive structural path for node {id}"));
    let path = path
        .iter()
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(".");
    format!("{REMAT_CONTIG_S_PREFIX}_{path}")
}

fn structural_path_to_node<B: SnarkBackend>(
    tree: &crate::irs::tree::Tree<B>,
    target: crate::irs::nodes::NodeId,
) -> Option<Vec<usize>> {
    fn visit<B: SnarkBackend>(
        node: &Arc<Node<B>>,
        target: crate::irs::nodes::NodeId,
        path: &mut Vec<usize>,
    ) -> bool {
        if node.id() == target {
            return true;
        }
        for (index, child) in node.children().iter().enumerate() {
            path.push(index);
            if visit(child, target, path) {
                return true;
            }
            path.pop();
        }
        false
    }

    let mut path = Vec::new();
    if visit(tree.root(), target, &mut path) {
        Some(path)
    } else {
        None
    }
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
