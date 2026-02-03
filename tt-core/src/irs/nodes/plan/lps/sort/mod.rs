use arithmetic::ACTIVATOR_COL_NAME;
use arithmetic::ROW_ID_COL_NAME;
use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion_expr::{Expr, LogicalPlan, col};
use indexmap::IndexMap;
use std::sync::Arc;

use crate::{
    irs::{
        nodes::{
            IsLpNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            gadget::lps::sort, hints::HintDF,
        },
        payloads::PayloadStructure,
        tree::Tree,
    },
    prover::irs::VirtualizedIr as ProverVirtualizedIr,
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
};
pub(crate) mod output;
use datafusion::logical_expr::Sort;
/// The implementation of a filter node in the prover proof tree.
pub struct LpNode<B>
where
    B: SnarkBackend,
{
    // The sort information from DataFusion
    sort: Sort,
    // The prover plan child node that is the input to this Sort
    input: Arc<Node<B>>,
    // The prover plan children nodes for the Sort expressions
    sort_exprs: Vec<Arc<Node<B>>>,
    // The gadget node for proving the sort operation
    gadget: Arc<Node<B>>,
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

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_hint_df = match planned_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(input_hint_df.data_frame().clone())
                .expect("sort input row-id sort should succeed");

        let mut exprs: Vec<Expr> = self
            .sort
            .expr
            .iter()
            .map(|sort_expr| sort_expr.expr.clone())
            .collect();
        // Keep row-id only for deterministic ordering; payloads strip it later.
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let sort_exprs_df = input_df
            .select(exprs)
            .expect("sort expr projection should succeed");
        let sort_exprs_df = crate::irs::nodes::hints::sort_by_row_id_if_present(sort_exprs_df)
            .expect("sort expr output sort should succeed");
        let sort_exprs_hint = HintDF::new_virtual(sort_exprs_df);

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(sort::INPUT_SORT_EXPRS.to_string(), sort_exprs_hint);
        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
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
        Ok(())
    }

    /// The gadget for the filter node only takes in 1. the input activator column, 2. the output activator column and 3. the binary output of the predicate column.
    /// Then the gadget proves to you that the output activator column is correctly computed from the input activator column and the predicate column.
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // 1) Gather the input/output tables for this sort node.
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => {
                // Drop row-id from gadget payloads while keeping it for ordering in plans.
                Some(strip_row_id_tracked_table(table))
            }
            _ => None,
        };
        let output_table =
            virtualized_ir
                .payload_for_node(&_id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => {
                        // Drop row-id from gadget payloads while keeping it for ordering in plans.
                        Some(strip_row_id_tracked_table(table))
                    }
                    _ => None,
                });

        // 2) Build a table that holds one column per sort expression plus a shared activator.
        let sort_exprs_table = build_sort_exprs_table_prover(&self.sort_exprs, virtualized_ir);

        // 3) Populate the gadget payload for the sort gadget node.
        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        if let Some(input) = input_table {
            gadget_payload.insert(sort::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = output_table {
            gadget_payload.insert(sort::OUTPUT_LABEL.to_string(), output);
        }
        if let Some(sort_exprs) = sort_exprs_table {
            gadget_payload.insert(sort::INPUT_SORT_EXPRS.to_string(), sort_exprs);
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // 1) Gather the input/output table oracles for this sort node.
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => {
                // Drop row-id from gadget payloads while keeping it for ordering in plans.
                Some(strip_row_id_tracked_oracle(table))
            }
            _ => None,
        };
        let output_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => {
                    // Drop row-id from gadget payloads while keeping it for ordering in plans.
                    Some(strip_row_id_tracked_oracle(table))
                }
                _ => None,
            });

        // 2) Build a table oracle that holds one column per sort expression plus a shared activator.
        let sort_exprs_table = build_sort_exprs_table_verifier(&self.sort_exprs, virtualized_ir);

        // 3) Populate the gadget payload for the sort gadget node.
        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        if let Some(input) = input_table {
            gadget_payload.insert(sort::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = output_table {
            gadget_payload.insert(sort::OUTPUT_LABEL.to_string(), output);
        }
        if let Some(sort_exprs) = sort_exprs_table {
            gadget_payload.insert(sort::INPUT_SORT_EXPRS.to_string(), sort_exprs);
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

fn build_sort_exprs_table_prover<B: SnarkBackend>(
    sort_exprs: &[Arc<Node<B>>],
    virtualized_ir: &ProverVirtualizedIr<B>,
) -> Option<TrackedTable<B>> {
    if sort_exprs.is_empty() {
        return None;
    }

    let mut output_cols: IndexMap<FieldRef, ark_piop::prover::structs::polynomial::TrackedPoly<B>> =
        IndexMap::new();
    let mut activator: Option<(FieldRef, _)> = None;
    let mut log_size: Option<usize> = None;
    let mut metadata = None;

    for expr_node in sort_exprs {
        let expr_table = match virtualized_ir.payload_for_node(&expr_node.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Sort expression missing tracked table payload"),
        };

        log_size.get_or_insert(expr_table.log_size());
        debug_assert_eq!(
            *log_size.as_ref().unwrap(),
            expr_table.log_size(),
            "Sort expr tables should share log size"
        );
        metadata.get_or_insert_with(|| {
            expr_table
                .schema_ref()
                .map(|schema| schema.metadata().clone())
                .unwrap_or_default()
        });

        if activator.is_none()
            && let Some(activator_poly) = expr_table.activator_tracked_poly()
        {
            let activator_field = expr_table
                .tracked_polys()
                .keys()
                .find(|field| field.name() == ACTIVATOR_COL_NAME)
                .cloned()
                .expect("activator field missing from sort expr table");
            activator = Some((activator_field, activator_poly));
        }
        let data_indices = expr_table.data_tracked_polys_indices();
        if data_indices.len() != 1 {
            panic!("Sort expression tables must have exactly one data column");
        }
        let expr_tracked = expr_table.tracked_polys();
        let (field, poly) = expr_tracked
            .get_index(data_indices[0])
            .expect("sort expr column index out of bounds");
        output_cols.insert(field.clone(), poly.clone());
    }

    if let Some((field, poly)) = activator {
        output_cols.entry(field).or_insert(poly);
    }
    // Do not include row-id in gadget payloads; it is only used for ordering in plans.

    let fields: Vec<Field> = output_cols
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(
        fields,
        metadata.unwrap_or_default(),
    ));
    Some(TrackedTable::new(
        schema,
        output_cols,
        log_size.unwrap_or_default(),
    ))
}

fn build_sort_exprs_table_verifier<B: SnarkBackend>(
    sort_exprs: &[Arc<Node<B>>],
    virtualized_ir: &VerifierVirtualizedIr<B>,
) -> Option<TrackedTableOracle<B>> {
    if sort_exprs.is_empty() {
        return None;
    }

    let mut output_cols: IndexMap<FieldRef, ark_piop::verifier::structs::oracle::TrackedOracle<B>> =
        IndexMap::new();
    let mut activator: Option<(FieldRef, _)> = None;
    let mut log_size: Option<usize> = None;
    let mut metadata = None;

    for expr_node in sort_exprs {
        let expr_table = match virtualized_ir.payload_for_node(&expr_node.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Sort expression missing tracked table payload"),
        };

        log_size.get_or_insert(expr_table.log_size());
        debug_assert_eq!(
            *log_size.as_ref().unwrap(),
            expr_table.log_size(),
            "Sort expr tables should share log size"
        );
        metadata.get_or_insert_with(|| {
            expr_table
                .schema_ref()
                .map(|schema| schema.metadata().clone())
                .unwrap_or_default()
        });

        if activator.is_none()
            && let Some(activator_oracle) = expr_table.activator_tracked_poly()
        {
            let activator_field = expr_table
                .tracked_oracles()
                .keys()
                .find(|field| field.name() == ACTIVATOR_COL_NAME)
                .cloned()
                .expect("activator field missing from sort expr table");
            activator = Some((activator_field, activator_oracle));
        }
        let data_indices = expr_table.data_tracked_oracles_indices();
        if data_indices.len() != 1 {
            panic!("Sort expression tables must have exactly one data column");
        }
        let expr_tracked = expr_table.tracked_oracles();
        let (field, oracle) = expr_tracked
            .get_index(data_indices[0])
            .expect("sort expr column index out of bounds");
        output_cols.insert(field.clone(), oracle.clone());
    }

    if let Some((field, oracle)) = activator {
        output_cols.entry(field).or_insert(oracle);
    }
    // Do not include row-id in gadget payloads; it is only used for ordering in plans.

    let fields: Vec<Field> = output_cols
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(
        fields,
        metadata.unwrap_or_default(),
    ));
    Some(TrackedTableOracle::new(
        schema,
        output_cols,
        log_size.unwrap_or_default(),
    ))
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

    fn output(&self) -> HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
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
                .fields()
                .iter()
                .filter_map(|field| (field.name() != ROW_ID_COL_NAME).then_some(col(field.name())))
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

        // Recurse into the input subtree and fetch the expr that feeds this
        // sort.
        let mut sort_exprs = vec![];
        for expr in &sort.expr {
            let expr_lp = Tree::<B>::from_expr(
                &expr.expr.clone(),
                Some(self_ref.clone()),
                Arc::downgrade(&input),
            )
            .root()
            .clone();
            sort_exprs.push(expr_lp);
        }

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(sort::GadgetNode::new(
            sort.clone(),
        ))));

        Self {
            sort,
            input,
            sort_exprs,
            gadget,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Sort(self.sort.clone())
    }
}
