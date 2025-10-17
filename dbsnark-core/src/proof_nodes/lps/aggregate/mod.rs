use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode,
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ctx::SharedCtx, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::{Schema, SchemaRef},
    common::Statistics,
    logical_expr::{
        self as df, ExprFunctionExt, ExprSchemable, JoinType, LogicalPlan, LogicalPlanBuilder,
        expr_rewriter::normalize_cols,
    },
    prelude::{Column, Expr, SessionContext},
};
use datafusion_functions_window::expr_fn::row_number;
use indexmap::IndexMap;
use ra_toolbox::lp_piop::aggregate_check::{AggregatePIOP, AggregatePIOPProverInput};
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub struct ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub aggr_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub input_proof_tree_root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}
// TODO: For the aggregation functions, we need some witnesses like the
// broadcast in max, etc TODO: For grouping expressions, we need to compute the
// multiplicity witness for the support check

pub struct VerifierAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub aggr_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub input_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the aggregate logical plan
        let aggregate = match &plan {
            LogicalPlan::Aggregate(agg) => agg,
            _ => panic!("expected aggregate logical plan"),
        };
        let node_id = NodeId::LP(plan.clone());
        // Recursively build the input proof tree
        let input_proof_tree_root = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &aggregate.input,
            &node_id,
        )
        .root();

        // Recursively build the children by first building a tree for the grouping
        // expressions Note that their parent logical plan is unusually set to
        // be the input logical plan of the aggregate
        let group_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = aggregate
            .group_expr
            .iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    &node_id.clone(),
                )
                .root()
            })
            .collect();

        // dbg!(
        //     &group_expr_proof_tree_roots
        //         .iter()
        //         .map(|n| n.node_id())
        //         .collect::<Vec<_>>()
        // );
        for expr in &aggregate.aggr_expr {
            if !matches!(expr, Expr::AggregateFunction(_)) {
                panic!(
                    "expected aggregate expression to be AggregateFunction, got
        {expr}"
                );
            }
        }
        let aggr_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = aggregate
            .aggr_expr
            .iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    &node_id.clone(),
                )
                .root()
            })
            .collect();

        Self {
            group_expr_proof_tree_roots,
            aggr_expr_proof_tree_roots,
            input_proof_tree_root,
            node_id,
        }
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::new();

        children.push(&self.input_proof_tree_root);
        self.group_expr_proof_tree_roots
            .iter()
            .for_each(|node| children.push(node));
        self.aggr_expr_proof_tree_roots
            .iter()
            .for_each(|node| children.push(node));

        children
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        // Extract the logical aggregate plan represented by this node.
        let aggregate_plan = match &self.node_id {
            NodeId::LP(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        };

        let base_plan = proof_tree
            .node(&self.input_proof_tree_root.node_id())
            .and_then(|node| {
                node.hint_generation_plans(proof_tree)
                    .get(OUTPUT_PLAN_KEY)
                    .map(|(plan, _)| plan.clone())
            })
            .expect("aggregate input missing OUTPUT_PLAN hint");

        // Delegate to the shared helper so prover and verifier expose identical hints.
        let output_plan = build_aggregate_hint_output_plan(base_plan, aggregate_plan);

        IndexMap::from([(OUTPUT_PLAN_KEY.to_string(), (output_plan, true))])
    }

    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> ProvingCost {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        self.input_proof_tree_root.clone()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        let Some(existing_output) = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
        else {
            return;
        };

        // Separate aggregate value columns and the activator from the current output
        // table.
        let mut aggregate_entries = Vec::new();
        let mut activator_entry = None;
        for (field, poly) in existing_output.tracked_polys() {
            if field.name() == ACTIVATOR_COL_NAME {
                activator_entry = Some((field, poly));
            } else {
                aggregate_entries.push((field, poly));
            }
        }

        // Collect the grouping expression columns produced by the child expression
        // nodes.
        let mut group_entries = Vec::with_capacity(self.group_expr_proof_tree_roots.len());
        for group_node in &self.group_expr_proof_tree_roots {
            // dbg!(&group_node.node_id());
            let Some(group_table) = piop_tree.tracked_table(&group_node.node_id(), OUTPUT_PLAN_KEY)
            else {
                return;
            };

            // dbg!(&group_table.tracked_polys().keys().collect::<Vec<_>>());

            let (field, poly) = group_table
                .tracked_polys()
                .into_iter()
                .find(|(field, _)| field.name() != ACTIVATOR_COL_NAME)
                .unwrap_or_else(|| {
                    panic!(
                        "group expression {} did not yield a data column",
                        group_node.name()
                    )
                });
            group_entries.push((field, poly));
        }
        // dbg!(&group_entries);

        if group_entries.is_empty() {
            return;
        }

        // Rebuild the output table so grouping columns appear first, followed by
        // aggregates and finally the activator column.
        let mut combined_columns = IndexMap::with_capacity(
            group_entries.len() + aggregate_entries.len() + usize::from(activator_entry.is_some()),
        );
        for (field, poly) in group_entries {
            combined_columns.insert(field, poly);
        }
        for (field, poly) in aggregate_entries {
            combined_columns.insert(field, poly);
        }
        if let Some((field, poly)) = activator_entry {
            combined_columns.insert(field, poly);
        }

        let schema_fields = combined_columns
            .keys()
            .map(|field_ref| field_ref.as_ref().clone())
            .collect::<Vec<_>>();
        let updated_table = TrackedTable::new(
            Some(Schema::new(schema_fields)),
            combined_columns,
            existing_output.log_size(),
        );
        // dbg!(&updated_table.tracked_polys().keys().collect::<Vec<_>>());

        piop_tree.add_table(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_string(),
            updated_table,
        );
    }
    fn prove_piop(
        &self,
        prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let aggregate = match &self.node_id {
            NodeId::LP(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        }
        .clone();

        let mut grouping_columns: IndexMap<
            datafusion::arrow::datatypes::FieldRef,
            ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>,
        > = IndexMap::new();
        let mut grouping_table_log_size: Option<usize> = None;

        for group_node in &self.group_expr_proof_tree_roots {
            let table = piop_tree
                .tracked_table(&group_node.node_id(), OUTPUT_PLAN_KEY)
                .unwrap_or_else(|| {
                    panic!(
                        "missing output_plan table for group expr {}",
                        group_node.name()
                    )
                });

            let table_log_size = table.log_size();
            if let Some(expected) = grouping_table_log_size {
                assert_eq!(
                    expected, table_log_size,
                    "grouping expression tables must have matching log sizes",
                );
            } else {
                grouping_table_log_size = Some(table_log_size);
            }

            for (field, poly) in table.tracked_polys() {
                if field.name() == ACTIVATOR_COL_NAME {
                    continue;
                }
                grouping_columns.insert(field.clone(), poly.clone());
            }
        }

        let input_grouping_table = if grouping_columns.is_empty() {
            panic!("aggregate PIOP requires at least one grouping column");
        } else {
            TrackedTable::new(None, grouping_columns, grouping_table_log_size.unwrap_or(0))
        };

        let output_table = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| panic!("missing output_plan table for aggregate node"));
        let grouping_col_count = aggregate.group_expr.len();
        let mut output_grouping_columns = IndexMap::with_capacity(grouping_col_count);
        for (idx, (field, poly)) in output_table.tracked_polys().iter().enumerate() {
            if idx >= grouping_col_count {
                break;
            }
            output_grouping_columns.insert(field.clone(), poly.clone());
        }
        assert_eq!(
            output_grouping_columns.len(),
            grouping_col_count,
            "aggregate output table does not contain enough grouping columns",
        );
        let output_grouping_table =
            TrackedTable::new(None, output_grouping_columns, output_table.log_size());

        let aggregate_piop_prover_input: AggregatePIOPProverInput<F, MvPCS, UvPCS> =
            AggregatePIOPProverInput {
                aggregate,
                input_grouping_table,
                output_grouping_table,
            };
        AggregatePIOP::prove(prover, aggregate_piop_prover_input)
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::new();

        children.push(&self.input_proof_tree_root);
        self.group_expr_proof_tree_roots
            .iter()
            .for_each(|node| children.push(node));
        self.aggr_expr_proof_tree_roots
            .iter()
            .for_each(|node| children.push(node));

        children
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        // Extract the logical aggregate plan represented by this node.
        let aggregate_plan = match &self.node_id {
            NodeId::LP(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        };

        // Obtain the input plan exposed by the verifier child node.
        let base_plan = proof_tree
            .node(&self.input_proof_tree_root.node_id())
            .and_then(|node| {
                node.hint_generation_plans(proof_tree)
                    .get(OUTPUT_PLAN_KEY)
                    .map(|(plan, _)| plan.clone())
            })
            .expect("missing aggregate input output plan");

        // Delegate to the shared helper so prover and verifier expose identical hints.
        let output_plan = build_aggregate_hint_output_plan(base_plan, aggregate_plan);

        IndexMap::from([(OUTPUT_PLAN_KEY.to_string(), (output_plan, true))])
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        let Some(existing_output) = piop_tree
            .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
        else {
            return;
        };

        // Separate aggregate value columns and the activator from the current output
        // table.
        let mut aggregate_entries = Vec::new();
        let mut activator_entry = None;
        for (field, oracle) in existing_output.tracked_oracles() {
            if field.name() == ACTIVATOR_COL_NAME {
                activator_entry = Some((field, oracle));
            } else {
                aggregate_entries.push((field, oracle));
            }
        }

        // Collect the grouping expression columns produced by the verifier child nodes.
        let mut group_entries = Vec::with_capacity(self.group_expr_proof_tree_roots.len());
        for group_node in &self.group_expr_proof_tree_roots {
            let Some(group_table) =
                piop_tree.tracked_table_oracle(&group_node.node_id(), OUTPUT_PLAN_KEY)
            else {
                return;
            };

            let (field, oracle) = group_table
                .tracked_oracles()
                .into_iter()
                .find(|(field, _)| field.name() != ACTIVATOR_COL_NAME)
                .unwrap_or_else(|| {
                    panic!(
                        "group expression {} did not yield a data column",
                        group_node.name()
                    )
                });
            group_entries.push((field, oracle));
        }

        if group_entries.is_empty() {
            return;
        }

        let mut combined_columns = IndexMap::with_capacity(
            group_entries.len() + aggregate_entries.len() + usize::from(activator_entry.is_some()),
        );
        for (field, oracle) in group_entries {
            combined_columns.insert(field, oracle);
        }
        for (field, oracle) in aggregate_entries {
            combined_columns.insert(field, oracle);
        }
        if let Some((field, oracle)) = activator_entry {
            combined_columns.insert(field, oracle);
        }

        let schema_fields = combined_columns
            .keys()
            .map(|field_ref| field_ref.as_ref().clone())
            .collect::<Vec<_>>();
        let updated_table = TrackedTableOracle::new(
            Some(Schema::new(schema_fields)),
            combined_columns,
            existing_output.log_size(),
        );

        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_string(),
            updated_table,
        );
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        todo!()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }
}

// TODO: For the aggregation functions, we need some witnesses like the
// broadcast in max, etc TODO: For grouping expressions, we need to compute the
// multiplicity witness for the support check

/// Builds the logical hint plan shared by the prover and verifier.
/// The helper joins the aggregate results back to the base input so the
/// output keeps the input cardinality while zeroing out non-representative
/// rows via an updated activator column.
fn build_aggregate_hint_output_plan(
    base_plan: LogicalPlan,
    aggregate_plan: &df::Aggregate,
) -> LogicalPlan {
    // Preserve the activator column type so the synthetic flag respects upstream
    // typing.
    let activator_dtype = base_plan
        .schema()
        .field_with_unqualified_name(ACTIVATOR_COL_NAME)
        .expect("aggregate input missing activator column")
        .data_type()
        .clone();

    // Resolve grouping and aggregation expressions against the input schema.
    let group_exprs = normalize_cols(aggregate_plan.group_expr.clone(), &base_plan)
        .expect("normalize group expressions");
    let aggr_exprs = normalize_cols(aggregate_plan.aggr_expr.clone(), &base_plan)
        .expect("normalize aggregate expressions");

    // Run the logical aggregate once to obtain one row per group.
    let aggregated_plan = LogicalPlanBuilder::from(base_plan.clone())
        .aggregate(group_exprs.clone(), aggr_exprs.clone())
        .expect("build aggregate plan")
        .build()
        .expect("aggregate logical plan");

    // Suffix helper aliases to avoid name collisions between base and aggregate
    // rows.
    let base_group_aliases: Vec<String> = group_exprs
        .iter()
        .enumerate()
        .map(|(idx, _)| format!("__dbsnark_group_expr_{idx}_base"))
        .collect();
    let agg_group_aliases: Vec<String> = group_exprs
        .iter()
        .enumerate()
        .map(|(idx, _)| format!("__dbsnark_group_expr_{idx}_agg"))
        .collect();

    // Extend the base plan with the grouping expressions under deterministic
    // aliases.
    let base_schema = base_plan.schema();
    let mut base_projection_exprs: Vec<Expr> = base_schema
        .fields()
        .iter()
        .map(|field| df::col(field.name()))
        .collect();
    for (expr, alias) in group_exprs.iter().zip(base_group_aliases.iter()) {
        base_projection_exprs.push(expr.clone().alias(alias.clone()));
    }
    let base_with_groups = LogicalPlanBuilder::from(base_plan.clone())
        .project(base_projection_exprs)
        .expect("project base with groups")
        .build()
        .expect("base with groups plan");

    // Rename aggregate outputs so grouping columns align with the helper aliases
    // while recording the aggregate value names for the final projection.
    let aggregated_schema = aggregated_plan.schema();
    let mut aggregated_projection_exprs: Vec<Expr> =
        Vec::with_capacity(aggregated_schema.fields().len());
    let mut aggregate_value_aliases: Vec<String> = Vec::new();
    let mut aggregate_output_names: Vec<String> = Vec::new();
    for (idx, field) in aggregated_schema.fields().iter().enumerate() {
        let column_expr = df::col(field.name());
        if idx < agg_group_aliases.len() {
            aggregated_projection_exprs.push(column_expr.alias(agg_group_aliases[idx].clone()));
        } else {
            let agg_idx = idx - agg_group_aliases.len();
            let alias = format!("__dbsnark_aggr_expr_{agg_idx}");
            aggregated_projection_exprs.push(column_expr.alias(alias.clone()));
            aggregate_value_aliases.push(alias);
            aggregate_output_names.push(field.name().to_string());
        }
    }
    let aggregated_with_alias = LogicalPlanBuilder::from(aggregated_plan.clone())
        .project(aggregated_projection_exprs)
        .expect("alias aggregate outputs")
        .build()
        .expect("aggregate with aliases plan");

    // Join the aggregate results back to every base row on the grouping aliases.
    let left_join_cols: Vec<Column> = base_group_aliases
        .iter()
        .map(|alias| Column::from_name(alias.clone()))
        .collect();
    let right_join_cols: Vec<Column> = agg_group_aliases
        .iter()
        .map(|alias| Column::from_name(alias.clone()))
        .collect();
    let joined_plan = LogicalPlanBuilder::from(base_with_groups.clone())
        .join(
            aggregated_with_alias.clone(),
            JoinType::Inner,
            (left_join_cols, right_join_cols),
            None,
        )
        .expect("join aggregate outputs with base rows")
        .build()
        .expect("aggregate joined plan");

    // Compute row_number() per group to detect the representative row to keep
    // active.
    let partition_exprs: Vec<Expr> = base_group_aliases.iter().map(df::col).collect();
    let row_number_alias = "__dbsnark_group_row_number".to_string();
    let row_number_expr = row_number()
        .partition_by(partition_exprs)
        .build()
        .expect("build row_number() window expression")
        .alias(row_number_alias.clone());
    let joined_with_row_number = LogicalPlanBuilder::from(joined_plan.clone())
        .window(vec![row_number_expr])
        .expect("attach row_number window")
        .build()
        .expect("aggregate joined with row number plan");

    // Rewrite the activator so only the first row per group remains active.
    let window_schema = joined_with_row_number.schema();
    let zero_literal = df::lit(0u64)
        .cast_to(&activator_dtype, window_schema.as_ref())
        .expect("cast zero literal to activator dtype");
    let new_activator = df::when(
        df::col(&row_number_alias).eq(df::lit(1u64)),
        df::col(ACTIVATOR_COL_NAME),
    )
    .otherwise(zero_literal)
    .expect("build group representative activator")
    .alias(ACTIVATOR_COL_NAME.to_string());

    // Project aggregate values with their original names along with the new
    // activator.
    let mut final_projection_exprs: Vec<Expr> =
        Vec::with_capacity(aggregate_value_aliases.len() + 1);
    for (alias, original_name) in aggregate_value_aliases
        .iter()
        .zip(aggregate_output_names.iter())
    {
        final_projection_exprs.push(df::col(alias).alias(original_name.clone()));
    }
    final_projection_exprs.push(new_activator);

    LogicalPlanBuilder::from(joined_with_row_number)
        .project(final_projection_exprs)
        .expect("final aggregate hint projection")
        .build()
        .expect("aggregate hint output plan")
}
