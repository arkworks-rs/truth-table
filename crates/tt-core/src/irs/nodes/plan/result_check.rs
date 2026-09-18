use crate::irs::nodes::utils::result_check::ResultCheckMode;
use crate::irs::nodes::{
    IsLpNode, IsNode, IsPlanNode, Node, PlanNode, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;
use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, IntervalUnit, Schema};
use datafusion_common::{DFSchemaRef, DataFusionError};
use datafusion_expr::{
    Expr, LogicalPlan,
    logical_plan::{Extension, UserDefinedLogicalNode},
};
use indexmap::IndexMap;
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::hash::Hasher;
use std::sync::Arc;

pub struct LpNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
    gadget: Arc<Node<B>>,
    mode: ResultCheckMode,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "ResultCheck".to_string()
    }

    fn display(&self) -> String {
        format!(
            "ResultCheck ({:?})\nInput: {}",
            self.mode,
            self.input.name()
        )
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
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(existing_payload)) =
            virtualized_ir.payload_for_node(&self.gadget.id())
        else {
            return Ok(());
        };
        let Some(r_table) =
            existing_payload.get(crate::irs::nodes::utils::result_check::OUTPUT_LABEL)
        else {
            return Ok(());
        };
        let Some(PayloadStructure::PlanPayload(t_table)) =
            virtualized_ir.payload_for_node(&self.input.id())
        else {
            return Ok(());
        };

        let aligned_t = project_prover_table_for_result_check(t_table, r_table)?;
        let mut gadget_payload = existing_payload.clone();
        gadget_payload.insert(
            crate::irs::nodes::utils::result_check::INPUT_LABEL.to_string(),
            aligned_t,
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
        Self::new_with_mode(input, result_check.mode())
    }

    fn lp(&self) -> LogicalPlan {
        let input_lp = match self.input.as_ref() {
            Node::Plan(PlanNode::LpBased(node)) => node.lp(),
            _ => panic!("ResultCheck input must be an LP node"),
        };
        wrap_logical_plan_with_mode(input_lp, self.mode)
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
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(existing_payload)) =
            virtualized_ir.payload_for_node(&self.gadget.id())
        else {
            return Ok(());
        };
        let Some(r_table) =
            existing_payload.get(crate::irs::nodes::utils::result_check::OUTPUT_LABEL)
        else {
            return Ok(());
        };
        let Some(PayloadStructure::PlanPayload(t_table)) =
            virtualized_ir.payload_for_node(&self.input.id())
        else {
            return Ok(());
        };

        let aligned_t = project_verifier_table_for_result_check(t_table, r_table)?;
        let mut gadget_payload = existing_payload.clone();
        gadget_payload.insert(
            crate::irs::nodes::utils::result_check::INPUT_LABEL.to_string(),
            aligned_t,
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
    /// Construct the legacy bag-equality ResultCheck.
    pub fn new(input: Arc<Node<B>>) -> Self {
        Self::new_with_mode(input, ResultCheckMode::Bag)
    }

    pub fn new_with_mode(input: Arc<Node<B>>, mode: ResultCheckMode) -> Self {
        let gadget = Arc::new(Node::Gadget(Arc::new(
            crate::irs::nodes::utils::result_check::GadgetNode::<B>::new(mode),
        )));
        Self {
            input,
            gadget,
            mode,
        }
    }

    pub fn mode(&self) -> ResultCheckMode {
        self.mode
    }
}

fn project_prover_table_for_result_check<B: SnarkBackend>(
    input_t: &TrackedTable<B>,
    compact_r: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
    let input_schema = input_t
        .schema_ref()
        .ok_or_else(|| result_schema_error("internal result schema missing"))?;
    let compact_schema = compact_r
        .schema_ref()
        .ok_or_else(|| result_schema_error("public result schema missing"))?;
    validate_result_schema::<B>(input_schema, compact_schema)?;
    let mut projected = IndexMap::new();
    for field in compact_schema.fields() {
        let poly = if field.name() == ACTIVATOR_COL_NAME {
            input_t
                .activator_tracked_poly()
                .ok_or_else(|| result_schema_error("internal activator missing"))?
        } else {
            input_t
                .tracked_polys_iter()
                .find_map(|(candidate, poly)| {
                    (candidate.name() == field.name()).then_some(poly.clone())
                })
                .ok_or_else(|| {
                    result_schema_error(&format!(
                        "internal result column {} not found",
                        field.name()
                    ))
                })?
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
    let input_schema = input_t
        .schema_ref()
        .ok_or_else(|| result_schema_error("internal result schema missing"))?;
    let compact_schema = compact_r
        .schema_ref()
        .ok_or_else(|| result_schema_error("public result schema missing"))?;
    validate_result_schema::<B>(input_schema, compact_schema)?;
    let mut projected = IndexMap::new();
    for field in compact_schema.fields() {
        let oracle = if field.name() == ACTIVATOR_COL_NAME {
            input_t
                .activator_tracked_poly()
                .ok_or_else(|| result_schema_error("internal activator missing"))?
        } else {
            input_t
                .tracked_oracles_iter()
                .find_map(|(candidate, oracle)| {
                    (candidate.name() == field.name()).then_some(oracle.clone())
                })
                .ok_or_else(|| {
                    result_schema_error(&format!(
                        "internal result column {} not found",
                        field.name()
                    ))
                })?
        };
        projected.insert(field.clone(), oracle);
    }
    Ok(TrackedTableOracle::new(
        Some(compact_schema.clone()),
        projected,
        input_t.log_size(),
    ))
}

/// Check the verifier-supplied result against the query plan's typed schema.
///
/// Field values alone do not identify SQL values: for example, small positive
/// `Int64` and `UInt64` values have the same field encoding. ResultCheck must
/// therefore reject a public file whose names, types, nullability, or duplicate
/// layout differs from the proved plan before comparing row fingerprints.
/// This validator does not authenticate Arrow validity bits inside the proved
/// query: the current ResultCheck contract is field-encoding equality for a
/// NULL-free internal pipeline, not general SQL NULL-aware equality.
fn validate_result_schema<B: SnarkBackend>(
    input_schema: &Schema,
    public_schema: &Schema,
) -> ark_piop::errors::SnarkResult<()> {
    // The internal execution schema may retain the authenticated row-id used
    // to preserve operator order. Row ids are deliberately not query output
    // and are excluded from row fingerprints, so compare the public sequence
    // against every other internal field (including the activator).
    let input_fields: Vec<_> = input_schema
        .fields()
        .iter()
        .filter(|field| field.name() != arithmetic::ROW_ID_COL_NAME)
        .collect();
    if input_fields.len() != public_schema.fields().len() {
        return Err(result_schema_error(&format!(
            "public result has {} columns, but the proved query result has {}",
            public_schema.fields().len(),
            input_fields.len()
        )));
    }
    validate_public_result_encoding::<B::F>(public_schema)?;
    for (position, (input_field, public_field)) in
        input_fields.iter().zip(public_schema.fields()).enumerate()
    {
        if input_field.name() != public_field.name() {
            return Err(result_schema_error(&format!(
                "public result field {position} is out of order or has the wrong name"
            )));
        }
    }
    let mut seen = HashSet::new();
    for public_field in public_schema.fields() {
        if public_field.name() == arithmetic::ROW_ID_COL_NAME {
            return Err(result_schema_error(
                "public result must not expose the reserved row-id column",
            ));
        }
        if !seen.insert(public_field.name()) {
            return Err(result_schema_error("duplicate public result column name"));
        }
        let mut matching = input_fields
            .iter()
            .filter(|candidate| candidate.name() == public_field.name());
        let Some(input_field) = matching.next() else {
            return Err(result_schema_error(&format!(
                "public result column {} is not produced by the query",
                public_field.name()
            )));
        };
        if matching.next().is_some() {
            return Err(result_schema_error(&format!(
                "query result column {} is ambiguous",
                public_field.name()
            )));
        }
        // Activator nullability is an internal representation detail: the
        // shared ACTIVATOR_FIELD is declared nullable, while normalization
        // constructs a non-null Boolean column. It is not part of the visible
        // SQL schema, and both paths guarantee Boolean/non-NULL evaluations.
        let type_and_nullability_match = if public_field.name() == ACTIVATOR_COL_NAME {
            input_field.data_type() == &DataType::Boolean
                && public_field.data_type() == &DataType::Boolean
        } else {
            input_field.data_type() == public_field.data_type()
                && input_field.is_nullable() == public_field.is_nullable()
        };
        if !type_and_nullability_match {
            return Err(result_schema_error(&format!(
                "public result column {} has the wrong type or nullability: internal={input_field:?}, public={public_field:?}",
                public_field.name(),
            )));
        }
    }
    Ok(())
}

/// Reject public SQL types whose current field encoding is not injective.
///
/// Decimal256 is reduced modulo the field characteristic by the current
/// encoder. Decimal128 and the 128-bit MonthDayNano interval encoding are
/// injective only when the field is wider than 128 bits. Nested types are
/// checked recursively even though most are rejected earlier by today's query
/// and encoding pipelines.
pub fn validate_public_result_encoding<F: PrimeField>(
    schema: &Schema,
) -> ark_piop::errors::SnarkResult<()> {
    for field in schema.fields() {
        validate_public_data_type::<F>(field.data_type())?;
    }
    Ok(())
}

fn validate_public_data_type<F: PrimeField>(
    data_type: &DataType,
) -> ark_piop::errors::SnarkResult<()> {
    match data_type {
        DataType::Decimal256(_, _) => {
            return Err(result_schema_error(
                "Decimal256 public results are unsupported because their field encoding is not injective",
            ));
        }
        DataType::Decimal128(_, _) | DataType::Interval(IntervalUnit::MonthDayNano)
            if F::MODULUS_BIT_SIZE <= 128 =>
        {
            return Err(result_schema_error(
                "128-bit public values require a field wider than 128 bits",
            ));
        }
        DataType::List(field)
        | DataType::ListView(field)
        | DataType::FixedSizeList(field, _)
        | DataType::LargeList(field)
        | DataType::LargeListView(field)
        | DataType::Map(field, _) => validate_public_data_type::<F>(field.data_type())?,
        DataType::Struct(fields) => {
            for field in fields.iter() {
                validate_public_data_type::<F>(field.data_type())?;
            }
        }
        DataType::Union(fields, _) => {
            for (_, field) in fields.iter() {
                validate_public_data_type::<F>(field.data_type())?;
            }
        }
        DataType::Dictionary(key, value) => {
            validate_public_data_type::<F>(key)?;
            validate_public_data_type::<F>(value)?;
        }
        DataType::RunEndEncoded(run_ends, values) => {
            validate_public_data_type::<F>(run_ends.data_type())?;
            validate_public_data_type::<F>(values.data_type())?;
        }
        _ => {}
    }
    Ok(())
}

fn result_schema_error(message: &str) -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::VerifierError(
        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
            "ResultCheck: {message}"
        )),
    )
}

#[derive(Debug, Clone)]
pub struct ResultCheckLogicalNode {
    input: Arc<LogicalPlan>,
    schema: DFSchemaRef,
    mode: ResultCheckMode,
}

impl ResultCheckLogicalNode {
    /// Construct the legacy bag-equality ResultCheck.
    pub fn new(input: LogicalPlan) -> Self {
        Self::new_with_mode(input, ResultCheckMode::Bag)
    }

    pub fn new_with_mode(input: LogicalPlan, mode: ResultCheckMode) -> Self {
        let schema = input.schema().clone();
        Self {
            input: Arc::new(input),
            schema,
            mode,
        }
    }

    pub fn input(&self) -> &LogicalPlan {
        self.input.as_ref()
    }

    pub fn mode(&self) -> ResultCheckMode {
        self.mode
    }

    fn key(&self) -> String {
        format!("{:?}:{:?}", self.mode, self.input)
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

    /// ResultCheck is a pure pass-through: its output schema equals the
    /// child's schema and every output column IS the child's
    /// same-indexed column (no reordering, dropping, or synthesis). So
    /// the child needs exactly the same column indices the parent asks
    /// this node for.
    ///
    /// This override lets DataFusion's projection-pushdown optimizer
    /// see through the `AddResultCheck` wrapper. In the current
    /// prove-path plan shape
    /// (`ResultCheck > Projection(SELECT cols) > Filter > TableScan`)
    /// the user's `Projection` already sits below `ResultCheck` and
    /// blocks the walk on its own — the `TableScan.projection` ends
    /// up with just the referenced columns even without this override.
    /// But if a future plan rewrite ever puts `ResultCheck` directly
    /// above a `TableScan` or a table-shape-preserving node (any
    /// shape where the row-count and columns are the source table's),
    /// the default `None` return would block pushdown and force the
    /// TableScan to load every column of the source table. Overriding
    /// to `Some(vec![output_columns])` — the identity mapping — makes
    /// the pushdown work through this node regardless of what sits
    /// below it, at zero cost to the current shape.
    fn necessary_children_exprs(&self, output_columns: &[usize]) -> Option<Vec<Vec<usize>>> {
        Some(vec![output_columns.to_vec()])
    }

    fn fmt_for_explain(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ResultCheck: mode={:?}", self.mode)
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
        Ok(Arc::new(ResultCheckLogicalNode::new_with_mode(
            inputs.into_iter().next().unwrap(),
            self.mode,
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
    wrap_logical_plan_with_mode(input, ResultCheckMode::Bag)
}

pub fn wrap_logical_plan_with_mode(input: LogicalPlan, mode: ResultCheckMode) -> LogicalPlan {
    LogicalPlan::Extension(Extension {
        node: Arc::new(ResultCheckLogicalNode::new_with_mode(input, mode)),
    })
}

fn _result_check_key(plan: &LogicalPlan) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(format!("{plan:?}").as_bytes());
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::{
        ResultCheckLogicalNode, validate_public_result_encoding, validate_result_schema,
        wrap_logical_plan_with_mode,
    };
    use crate::irs::nodes::utils::result_check::ResultCheckMode;
    use arithmetic::ACTIVATOR_COL_NAME;
    use ark_piop::DefaultSnarkBackend;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_expr::{UserDefinedLogicalNode, logical_plan::builder::table_scan};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    use std::sync::Arc;

    #[test]
    fn logical_node_retains_mode_across_rewrites_and_identity() {
        let input = table_scan(
            Some("input"),
            &Schema::new(vec![Field::new("value", DataType::Int64, false)]),
            None,
        )
        .expect("table scan should be valid")
        .build()
        .expect("logical plan should be valid");
        let bag = ResultCheckLogicalNode::new(input.clone());
        let ordered =
            ResultCheckLogicalNode::new_with_mode(input.clone(), ResultCheckMode::Ordered);

        assert!(!bag.dyn_eq(&ordered));
        let mut bag_hash = DefaultHasher::new();
        bag.dyn_hash(&mut bag_hash);
        let mut ordered_hash = DefaultHasher::new();
        ordered.dyn_hash(&mut ordered_hash);
        assert_ne!(bag_hash.finish(), ordered_hash.finish());

        let rewritten = ordered
            .with_exprs_and_inputs(Vec::new(), vec![input.clone()])
            .expect("identity rewrite should succeed");
        let rewritten = rewritten
            .as_any()
            .downcast_ref::<ResultCheckLogicalNode>()
            .expect("rewrite should remain ResultCheck");
        assert_eq!(rewritten.mode(), ResultCheckMode::Ordered);

        let display = wrap_logical_plan_with_mode(input, ResultCheckMode::Ordered)
            .display_indent()
            .to_string();
        assert!(display.contains("ResultCheck: mode=Ordered"));
    }

    #[test]
    fn low_level_result_schema_rejects_an_omitted_column() {
        let input = Schema::new(vec![
            Field::new("left", DataType::Int64, false),
            Field::new("right", DataType::Int64, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]);
        let omitted = Schema::new(vec![
            Field::new("left", DataType::Int64, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]);

        assert!(validate_result_schema::<DefaultSnarkBackend>(&input, &omitted).is_err());
    }

    #[test]
    fn low_level_result_schema_rejects_reordered_columns() {
        let input = Schema::new(vec![
            Field::new("left", DataType::Int64, false),
            Field::new("right", DataType::Int64, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]);
        let reordered = Schema::new(vec![
            Field::new("right", DataType::Int64, false),
            Field::new("left", DataType::Int64, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]);

        assert!(validate_result_schema::<DefaultSnarkBackend>(&input, &reordered).is_err());
    }

    #[test]
    fn low_level_result_schema_rejects_the_reserved_row_id() {
        let schema = Schema::new(vec![
            Field::new(arithmetic::ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]);

        assert!(validate_result_schema::<DefaultSnarkBackend>(&schema, &schema).is_err());
    }

    #[test]
    fn public_result_encoding_rejects_nested_decimal256() {
        let schema = Schema::new(vec![Field::new(
            "values",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::Decimal256(76, 0),
                false,
            ))),
            false,
        )]);

        assert!(
            validate_public_result_encoding::<<DefaultSnarkBackend as ark_piop::SnarkBackend>::F>(
                &schema
            )
            .is_err()
        );
    }

    #[test]
    fn low_level_result_schema_accepts_the_exact_schema() {
        let schema = Schema::new(vec![
            Field::new("value", DataType::Int64, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]);

        assert!(validate_result_schema::<DefaultSnarkBackend>(&schema, &schema).is_ok());
    }

    #[test]
    fn low_level_result_schema_allows_internal_row_id_only() {
        let input = Schema::new(vec![
            Field::new("value", DataType::Int64, false),
            Field::new(arithmetic::ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, true),
        ]);
        let public = Schema::new(vec![
            Field::new("value", DataType::Int64, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]);

        assert!(validate_result_schema::<DefaultSnarkBackend>(&input, &public).is_ok());
    }
}
