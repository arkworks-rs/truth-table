use arithmetic::ACTIVATOR_COL_NAME;
use arithmetic::ROW_ID_COL_NAME;
use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_common::Column;
use datafusion_expr::{Expr, LogicalPlan, col};
use indexmap::IndexMap;
use std::sync::Arc;

use crate::irs::nodes::hints::HintDF;
use crate::{
    irs::{
        nodes::{IsLpNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
        tree::Tree,
    },
    prover::irs::VirtualizedIr as ProverVirtualizedIr,
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
};
pub mod gadget;
pub(crate) mod output;
#[cfg(test)]
mod tests;
use datafusion::logical_expr::Sort;
/// ORDER BY: prove a permutation of the input and sorted keys of that output.
pub struct LpNode<B>
where
    B: SnarkBackend,
{
    // The sort information from DataFusion
    sort: Sort,
    // The prover plan child node that is the input to this Sort
    input: Arc<Node<B>>,
    // Input-scoped expression children retained for acyclic planning only.
    // The proof does not trust their payloads as the sorted output keys.
    sort_exprs: Vec<Arc<Node<B>>>,
    // The gadget node for proving the sort operation
    gadget: Arc<Node<B>>,
    // Tree construction is infallible, so unsupported keys are recorded and
    // rejected by every fallible prover/verifier pass before proof work starts.
    validation_error: Option<String>,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "Order By".to_string()
    }

    fn display(&self) -> String {
        let exprs = if self.sort_exprs.is_empty() {
            "none".to_string()
        } else {
            self.sort_exprs
                .iter()
                .map(|node| node.name())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let fetch = self
            .sort
            .fetch
            .map(|val| val.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "Order By\nInput: {}, exprs: {}, fetch: {}",
            self.input.name(),
            exprs,
            fetch
        )
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        let mut children = vec![self.input.clone()];
        children.extend(self.sort_exprs.iter().cloned());
        children.push(self.gadget.clone());
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()
    }

    /// Connect the output's actual key expressions to the sorting gadget.
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()?;
        // Gather the input/output tables for this sort node.
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => {
                // Drop row-id from gadget payloads while keeping it for ordering in plans.
                strip_row_id_tracked_table(table)
            }
            _ => {
                return Err(ark_piop::errors::SnarkError::Artifact(
                    "ORDER BY input table is missing".to_string(),
                ));
            }
        };
        let output_source = match virtualized_ir.payload_for_node(&_id) {
            Some(PayloadStructure::PlanPayload(table)) => table,
            _ => {
                return Err(ark_piop::errors::SnarkError::Artifact(
                    "ORDER BY output table is missing".to_string(),
                ));
            }
        };
        // Sortcheck consumes keys selected from the tracked output itself.
        // Expression-child payloads are deliberately not trusted here: an
        // independently sorted helper must never validate an unsorted output.
        let sort_exprs_table = build_output_sort_keys_prover(output_source, &self.sort)?;
        // Drop row-id from the row-permutation payload while retaining it in
        // the plan output used for deterministic execution.
        let output_table = strip_row_id_tracked_table(output_source);

        // Populate the ORDER gadget from the row tables and exact output keys.
        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(gadget::INPUT_LABEL.to_string(), input_table);
        gadget_payload.insert(gadget::OUTPUT_LABEL.to_string(), output_table);
        gadget_payload.insert(gadget::OUTPUT_SORT_EXPRS.to_string(), sort_exprs_table);

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()?;
        let output_hint_df = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => {
                return Err(ark_piop::errors::SnarkError::Artifact(
                    "ORDER BY output planning payload is missing".to_string(),
                ));
            }
        };
        let sort_exprs_hint = build_output_sort_exprs_hint(&output_hint_df, &self.sort)?;

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(gadget::OUTPUT_SORT_EXPRS.to_string(), sort_exprs_hint);
        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()
    }
    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()?;
        // Gather the input/output table oracles for this sort node.
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => {
                // Drop row-id from gadget payloads while keeping it for ordering in plans.
                strip_row_id_tracked_oracle(table)
            }
            _ => {
                return Err(ark_piop::errors::SnarkError::Artifact(
                    "ORDER BY input table oracle is missing".to_string(),
                ));
            }
        };
        let output_source = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table,
            _ => {
                return Err(ark_piop::errors::SnarkError::Artifact(
                    "ORDER BY output table oracle is missing".to_string(),
                ));
            }
        };
        // Mirror the prover exactly: select key oracles from the tracked
        // output, never from a separately generated sort-expression witness.
        let sort_exprs_table = build_output_sort_keys_verifier(output_source, &self.sort)?;
        let output_table = strip_row_id_tracked_oracle(output_source);

        // Populate the ORDER gadget from the row tables and exact output keys.
        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(gadget::INPUT_LABEL.to_string(), input_table);
        gadget_payload.insert(gadget::OUTPUT_LABEL.to_string(), output_table);
        gadget_payload.insert(gadget::OUTPUT_SORT_EXPRS.to_string(), sort_exprs_table);

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()?;
        let output_hint_df = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => {
                return Err(ark_piop::errors::SnarkError::Artifact(
                    "ORDER BY output planning payload is missing".to_string(),
                ));
            }
        };
        // Use the same output-scoped projection as the prover. Expression
        // children remain planning-only and cannot silently change verifier
        // key identity or disappear from the checked schema.
        let sort_exprs_hint = build_output_sort_exprs_hint(&output_hint_df, &self.sort)?;

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(gadget::OUTPUT_SORT_EXPRS.to_string(), sort_exprs_hint);
        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }
}

const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";

fn checked_sort_column(
    sort_expr: &datafusion_expr::SortExpr,
) -> ark_piop::errors::SnarkResult<&Column> {
    match &sort_expr.expr {
        Expr::Column(column) => Ok(column),
        _ => Err(ark_piop::errors::SnarkError::Artifact(
            "ORDER BY key was not a validated direct column".to_string(),
        )),
    }
}

fn canonical_sort_key(
    sort: &Sort,
    sort_expr: &datafusion_expr::SortExpr,
) -> ark_piop::errors::SnarkResult<(Column, DataType)> {
    let requested = checked_sort_column(sort_expr)?;
    let (qualifier, field) = sort
        .input
        .schema()
        .qualified_field_from_column(requested)
        .map_err(|error| {
            ark_piop::errors::SnarkError::Artifact(format!(
                "ORDER BY key `{requested}` does not resolve uniquely: {error}"
            ))
        })?;
    Ok((
        Column::new(qualifier.cloned(), field.name()),
        field.data_type().clone(),
    ))
}

fn field_matches_sort_column(field: &Field, column: &Column) -> bool {
    if field.name() != column.name() {
        return false;
    }
    match column.relation.as_ref() {
        Some(relation) => field
            .metadata()
            .get(QUALIFIER_METADATA_KEY)
            .is_some_and(|qualifier| qualifier == &relation.to_string()),
        None => !field.metadata().contains_key(QUALIFIER_METADATA_KEY),
    }
}

fn validate_output_key_field(
    field: &Field,
    column: &Column,
    expected_type: &DataType,
) -> ark_piop::errors::SnarkResult<()> {
    if field.is_nullable() {
        return Err(ark_piop::errors::SnarkError::Artifact(format!(
            "tracked ORDER BY output key `{column}` is nullable"
        )));
    }
    if !gadget::is_supported_sort_type(field.data_type()) {
        return Err(ark_piop::errors::SnarkError::Artifact(format!(
            "tracked ORDER BY output key `{column}` has unsupported type `{}`",
            field.data_type()
        )));
    }
    if field.data_type() != expected_type {
        return Err(ark_piop::errors::SnarkError::Artifact(format!(
            "tracked ORDER BY output key `{column}` has type `{}`, expected `{expected_type}`",
            field.data_type()
        )));
    }
    Ok(())
}

fn validate_output_activator_field(field: &Field) -> ark_piop::errors::SnarkResult<()> {
    if field.data_type() != &DataType::Boolean {
        return Err(ark_piop::errors::SnarkError::Artifact(format!(
            "ORDER BY output activator must be Boolean, got `{field}`"
        )));
    }
    Ok(())
}

fn build_output_sort_keys_prover<B: SnarkBackend>(
    output: &TrackedTable<B>,
    sort: &Sort,
) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
    let tracked = output.tracked_polys();
    let data_indices = output.data_tracked_polys_indices();
    let mut columns = IndexMap::new();
    for sort_expr in &sort.expr {
        let (column, expected_type) = canonical_sort_key(sort, sort_expr)?;
        let matches = data_indices
            .iter()
            .copied()
            .filter(|idx| {
                tracked
                    .get_index(*idx)
                    .is_some_and(|(field, _)| field_matches_sort_column(field, &column))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(ark_piop::errors::SnarkError::Artifact(format!(
                "ORDER BY output key `{column}` resolved to {} tracked columns",
                matches.len()
            )));
        }
        let (field, poly) = tracked
            .get_index(matches[0])
            .expect("checked ORDER BY output index should exist");
        validate_output_key_field(field, &column, &expected_type)?;
        columns.insert(field.clone(), poly.clone());
    }
    if columns.len() != sort.expr.len() {
        return Err(ark_piop::errors::SnarkError::Artifact(
            "ORDER BY output key count does not match the logical sort".to_string(),
        ));
    }
    let mut activators = tracked
        .iter()
        .filter(|(field, _)| field.name() == ACTIVATOR_COL_NAME);
    let (active_field, active_poly) = activators.next().ok_or_else(|| {
        ark_piop::errors::SnarkError::Artifact("ORDER BY output activator is missing".to_string())
    })?;
    if activators.next().is_some() {
        return Err(ark_piop::errors::SnarkError::Artifact(
            "ORDER BY output has multiple activator columns".to_string(),
        ));
    }
    validate_output_activator_field(active_field)?;
    columns.insert(active_field.clone(), active_poly.clone());
    let fields = columns
        .keys()
        .map(|field| field.as_ref().clone())
        .collect::<Vec<_>>();
    let metadata = output
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    Ok(TrackedTable::new(
        Some(Schema::new_with_metadata(fields, metadata)),
        columns,
        output.log_size(),
    ))
}

fn build_output_sort_keys_verifier<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
    sort: &Sort,
) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
    let tracked = output.tracked_oracles();
    let data_indices = output.data_tracked_oracles_indices();
    let mut columns = IndexMap::new();
    for sort_expr in &sort.expr {
        let (column, expected_type) = canonical_sort_key(sort, sort_expr)?;
        let matches = data_indices
            .iter()
            .copied()
            .filter(|idx| {
                tracked
                    .get_index(*idx)
                    .is_some_and(|(field, _)| field_matches_sort_column(field, &column))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(ark_piop::errors::SnarkError::Artifact(format!(
                "ORDER BY output key `{column}` resolved to {} tracked oracles",
                matches.len()
            )));
        }
        let (field, oracle) = tracked
            .get_index(matches[0])
            .expect("checked ORDER BY output oracle index should exist");
        validate_output_key_field(field, &column, &expected_type)?;
        columns.insert(field.clone(), oracle.clone());
    }
    if columns.len() != sort.expr.len() {
        return Err(ark_piop::errors::SnarkError::Artifact(
            "ORDER BY output key-oracle count does not match the logical sort".to_string(),
        ));
    }
    let mut activators = tracked
        .iter()
        .filter(|(field, _)| field.name() == ACTIVATOR_COL_NAME);
    let (active_field, active_oracle) = activators.next().ok_or_else(|| {
        ark_piop::errors::SnarkError::Artifact(
            "ORDER BY output activator oracle is missing".to_string(),
        )
    })?;
    if activators.next().is_some() {
        return Err(ark_piop::errors::SnarkError::Artifact(
            "ORDER BY output has multiple activator oracles".to_string(),
        ));
    }
    validate_output_activator_field(active_field)?;
    columns.insert(active_field.clone(), active_oracle.clone());
    let fields = columns
        .keys()
        .map(|field| field.as_ref().clone())
        .collect::<Vec<_>>();
    let metadata = output
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    Ok(TrackedTableOracle::new(
        Some(Schema::new_with_metadata(fields, metadata)),
        columns,
        output.log_size(),
    ))
}

fn build_output_sort_exprs_hint(
    output_hint: &HintDF,
    sort: &Sort,
) -> ark_piop::errors::SnarkResult<HintDF> {
    let output_df = output_hint.data_frame().clone();
    let mut exprs = output::resolve_sort_exprs(output_df.schema(), &sort.expr)
        .into_iter()
        .map(|sort_expr| sort_expr.expr)
        .collect::<Vec<_>>();
    if output_df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME)
    {
        exprs.push(col(ACTIVATOR_COL_NAME));
    }
    // Row id is an auxiliary deterministic-ordering key and is removed before
    // the actual tracked output keys are passed to Sortcheck.
    crate::irs::nodes::hints::append_row_id_expr_if_present(&output_df, &mut exprs);
    let key_df = output_df.select(exprs).map_err(|error| {
        ark_piop::errors::SnarkError::Artifact(format!(
            "ORDER BY output key projection failed: {error}"
        ))
    })?;
    let key_df = crate::irs::nodes::hints::sort_by_row_id_if_present(key_df).map_err(|error| {
        ark_piop::errors::SnarkError::Artifact(format!(
            "ORDER BY output key ordering failed: {error}"
        ))
    })?;
    Ok(HintDF::new_virtual(key_df))
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

    // Row-id is only used for deterministic ordering, so omit it from payload tables.
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

    // Row-id is only used for deterministic ordering, so omit it from payload tables.
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

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode<B> {
    fn output(&self) -> HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Sort input cannot be a gadget node"),
        };

        let output_df = output::sort_df(input_hint_df.data_frame(), &self.sort);
        let output_df = if output_df
            .schema()
            .fields()
            .iter()
            .any(|field| field.name() == ROW_ID_COL_NAME)
        {
            let projected = output_df
                .schema()
                .iter()
                .filter_map(|(qualifier, field)| {
                    (field.name() != ROW_ID_COL_NAME)
                        .then_some(Expr::Column(Column::new(qualifier.cloned(), field.name())))
                })
                .collect();
            output_df
                .select(projected)
                .expect("sort output projection should succeed")
        } else {
            output_df
        };
        HintDF::new_materialized(output_df)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Sort input cannot be a gadget node"),
        };

        let input_df = input_hint_df.data_frame().clone();
        let output_exprs = input_df
            .schema()
            .iter()
            .filter_map(|(qualifier, field)| {
                (field.name() != ROW_ID_COL_NAME)
                    .then_some(Expr::Column(Column::new(qualifier.cloned(), field.name())))
            })
            .collect();
        // Project the schema-only verifier DataFrame instead of rebuilding it
        // from bare Arrow fields; rebuilding would erase relation qualifiers
        // needed to bind joined-table keys unambiguously.
        let output_df = input_df
            .select(output_exprs)
            .expect("sort verifier output projection should succeed");
        HintDF::new_materialized(output_df)
    }
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(plan: LogicalPlan, self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let sort = match plan {
            LogicalPlan::Sort(sort) => sort,
            _ => panic!("Expected LogicalPlan::Sort"),
        };

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // sort.
        let input = Tree::<B>::from_logical_plan(&sort.input).root().clone();

        // Keep expression children acyclic for planning. They are not trusted
        // by the proof: `initialize_gadgets` selects the checked direct-column
        // commitments from this Sort node's tracked output table itself.
        let validation_error = gadget::validate_sort(&sort).err();
        let mut sort_exprs = vec![];
        if validation_error.is_none() {
            for expr in &sort.expr {
                let expr_lp = Tree::<B>::from_expr(
                    &expr.expr.clone(),
                    Some(self_ref.clone()),
                    vec![Arc::downgrade(&input)],
                )
                .root()
                .clone();
                sort_exprs.push(expr_lp);
            }
        }

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(gadget::GadgetNode::new(
            sort.clone(),
        ))));

        Self {
            sort,
            input,
            sort_exprs,
            gadget,
            validation_error,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Sort(self.sort.clone())
    }
}

impl<B: SnarkBackend> LpNode<B> {
    fn ensure_valid(&self) -> ark_piop::errors::SnarkResult<()> {
        match &self.validation_error {
            Some(message) => Err(ark_piop::errors::SnarkError::Artifact(message.clone())),
            None => Ok(()),
        }
    }
}
