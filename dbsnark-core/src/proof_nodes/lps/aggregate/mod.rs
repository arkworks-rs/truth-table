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
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, Schema, SchemaRef},
    common::{Statistics, TableReference},
    logical_expr::{
        self as df, Case, ExprFunctionExt, ExprSchemable, JoinType, LogicalPlan,
        LogicalPlanBuilder, Operator, expr_rewriter::normalize_cols,
    },
    prelude::{Column, Expr, SessionContext},
    scalar::ScalarValue,
};
use datafusion_expr::WindowFrame;
use datafusion_functions_aggregate::count::count_all;
use datafusion_functions_window::expr_fn::row_number;
use indexmap::IndexMap;
use ra_toolbox::lp_piop::aggregate_check::{
    AggregatePIOP, AggregatePIOPProverInput, AggregatePIOPProverOutput,
    AggregatePIOPVerifierInput, AggregatePIOPVerifierOutput,
};
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub(crate) const GROUP_MULTIPLICITY_COL_NAME: &str = "__dbsnark_group_multiplicity";
const MULTIPLICITY_PLAN_KEY: &str = "multiplicity";
pub(crate) const GROUP_INPUT_FOLDED_COL_NAME: &str = "__dbsnark_group_input_folded";
pub(crate) const GROUP_OUTPUT_FOLDED_COL_NAME: &str = "__dbsnark_group_output_folded";

pub(crate) fn grouping_multiplicity_field() -> Arc<Field> {
    Arc::new(Field::new(
        GROUP_MULTIPLICITY_COL_NAME,
        DataType::UInt64,
        true,
    ))
}

pub(crate) fn grouping_input_folded_field() -> Arc<Field> {
    Arc::new(Field::new(
        GROUP_INPUT_FOLDED_COL_NAME,
        DataType::Binary,
        true,
    ))
}

pub(crate) fn grouping_output_folded_field() -> Arc<Field> {
    Arc::new(Field::new(
        GROUP_OUTPUT_FOLDED_COL_NAME,
        DataType::Binary,
        true,
    ))
}

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
        // Get the node id of the current node
        let node_id = NodeId::LP(plan.clone());
        // Recursively build the input proof tree
        let input_proof_tree_root = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &aggregate.input,
            &node_id,
        )
        .root();

        // Recursively build the children by first building trees for the grouping
        // expressions
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

        // Recursively build the children by first building trees for the eggregation
        // expressions
        let aggr_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = aggregate
            .aggr_expr
            .iter()
            .map(|expr| {
                if !matches!(expr, Expr::AggregateFunction(_)) {
                    panic!(
                        "expected aggregate expression to be AggregateFunction, got
        {expr}"
                    );
                }
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
        // Note that the leftmost child is always the node corresponding to the input
        // logical plans This is crucial when traversing the proof tree in a
        // post-order fashion
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
        let output_plan = build_aggregate_hint_output_plan(base_plan.clone(), aggregate_plan);
        let multiplicity_plan = build_aggregate_multiplicity_hint_plan(base_plan, aggregate_plan);

        IndexMap::from([
            (OUTPUT_PLAN_KEY.to_string(), (output_plan, true)),
            (MULTIPLICITY_PLAN_KEY.to_string(), (multiplicity_plan, true)),
        ])
    }

    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> ProvingCost {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        self.input_proof_tree_root.clone()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        // Fetch the current output table tracked by this aggregate node
        // This should contain only the materialized columns; i.e. the new activator and
        // the aggregate expression columns
        // It remains to attach the grouping expression columns at the front
        let Some(existing_output) = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
        else {
            panic!("missing output plan table for the current aggregate node");
        };

        // Separate aggregate value columns and the activator from the current output
        // table.
        let aggregate_plan = match self.node_id.to_lp() {
            Some(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        };
        let group_col_count = aggregate_plan.group_expr.len();
        let aggregate_col_count = aggregate_plan.aggr_expr.len();

        let mut aggregate_entries = Vec::new();
        let mut passthrough_entries = Vec::new();
        let mut activator_entry = None;
        for (idx, (field, poly)) in existing_output.tracked_polys().into_iter().enumerate() {
            if field.name() == ACTIVATOR_COL_NAME {
                activator_entry = Some((field, poly));
            } else if idx >= group_col_count && idx < group_col_count + aggregate_col_count {
                aggregate_entries.push((field, poly));
            } else if idx >= group_col_count + aggregate_col_count {
                passthrough_entries.push((field, poly));
            } else {
                // These correspond to grouping columns; they will be populated
                // from the child group expression nodes below.
            }
        }

        if !self.aggr_expr_proof_tree_roots.is_empty() {
            if aggregate_entries.len() != self.aggr_expr_proof_tree_roots.len() {
                panic!(
                    "aggregate expressions count mismatch: expected {}, found {}",
                    self.aggr_expr_proof_tree_roots.len(),
                    aggregate_entries.len()
                );
            }

            let (activator_field, activator_poly) = activator_entry
                .as_ref()
                .unwrap_or_else(|| panic!("aggregate output missing activator column"));

            for (idx, aggr_node) in self.aggr_expr_proof_tree_roots.iter().enumerate() {
                let (agg_field, agg_poly) = aggregate_entries
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| panic!("missing aggregate entry for {}", aggr_node.name()));

                let mut columns = IndexMap::with_capacity(2);
                columns.insert(agg_field, agg_poly);
                columns.insert(activator_field.clone(), activator_poly.clone());

                let agg_child_table = TrackedTable::new(None, columns, existing_output.log_size());

                piop_tree.add_table(
                    aggr_node.node_id(),
                    OUTPUT_PLAN_KEY.to_string(),
                    agg_child_table,
                );
            }
        }

        // Collect the grouping expression columns produced by the child expression
        // nodes.
        let mut group_entries = Vec::with_capacity(self.group_expr_proof_tree_roots.len());
        for group_node in &self.group_expr_proof_tree_roots {
            let Some(group_table) = piop_tree.tracked_table(&group_node.node_id(), OUTPUT_PLAN_KEY)
            else {
                return;
            };

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

        if group_entries.is_empty() {
            panic!("no grouping expressions found for aggregate node");
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
            if combined_columns.contains_key(&field) {
                continue;
            }
            combined_columns.insert(field, poly);
        }
        for (field, poly) in passthrough_entries {
            if combined_columns.contains_key(&field) {
                continue;
            }
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

        let input_base_table = piop_tree
            .tracked_table(&self.input_proof_tree_root.node_id(), OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| panic!("missing output_plan table for aggregate input"));

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

        if let Some((field, poly)) = input_base_table
            .tracked_polys()
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
        {
            grouping_columns.insert(field, poly);
        }

        let input_grouping_table = TrackedTable::new(
            None,
            grouping_columns,
            grouping_table_log_size.unwrap_or_else(|| input_base_table.log_size()),
        );
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
        if let Some((field, poly)) = output_table
            .tracked_polys()
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
        {
            output_grouping_columns.insert(field, poly);
        }
        let output_grouping_table =
            TrackedTable::new(None, output_grouping_columns, output_table.log_size());

        let aggregate_piop_prover_input: AggregatePIOPProverInput<F, MvPCS, UvPCS> =
            AggregatePIOPProverInput {
                aggregate,
                input_grouping_table,
                output_grouping_table,
            };
        let aggregate_piop_prover_output =
            AggregatePIOP::prove(prover, aggregate_piop_prover_input)?;
        let AggregatePIOPProverOutput {
            grouping_multiplicty_tracked_poly: grouping_multiplicity_poly,
            input_folded_tracked_col,
            output_folded_tracked_col,
        } = aggregate_piop_prover_output;
        debug_assert_eq!(
            grouping_multiplicity_poly.log_size(),
            input_folded_tracked_col.log_size(),
            "folded input column log size mismatch with multiplicity"
        );
        debug_assert_eq!(
            grouping_multiplicity_poly.log_size(),
            output_folded_tracked_col.log_size(),
            "folded output column log size mismatch with multiplicity"
        );
        let multiplicity_log_size = grouping_multiplicity_poly.log_size();
        let multiplicity_field = grouping_multiplicity_field();
        let mut columns = IndexMap::new();
        columns.insert(multiplicity_field, grouping_multiplicity_poly);
        columns.insert(
            grouping_input_folded_field(),
            input_folded_tracked_col.data_tracked_poly(),
        );
        columns.insert(
            grouping_output_folded_field(),
            output_folded_tracked_col.data_tracked_poly(),
        );
        let auxiliary_table = TrackedTable::new(None, columns, multiplicity_log_size);
        piop_tree.add_table(
            self.node_id.clone(),
            "auxiliary".to_string(),
            auxiliary_table,
        );

        self.children()
            .iter()
            .try_for_each(|child| child.prove_piop(prover, piop_tree))?;
        Ok(())
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
        verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
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
        let input_proof_tree_root = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            verifier_ctx.clone(),
            &aggregate.input,
            &node_id,
        )
        .root();

        // Recursively build the children by first building a tree for the grouping
        // expressions Note that their parent logical plan is unusually set to
        // be the input logical plan of the aggregate
        let group_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> = aggregate
            .group_expr
            .iter()
            .map(|expr| {
                VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    expr.clone(),
                    &node_id.clone(),
                )
                .root()
            })
            .collect();

        for expr in &aggregate.aggr_expr {
            if !matches!(expr, Expr::AggregateFunction(_)) {
                panic!(
                    "expected aggregate expression to be AggregateFunction, got
        {expr}"
                );
            }
        }
        let aggr_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> = aggregate
            .aggr_expr
            .iter()
            .map(|expr| {
                VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
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
        let output_plan = build_aggregate_hint_output_plan(base_plan.clone(), aggregate_plan);
        let multiplicity_plan = build_aggregate_multiplicity_hint_plan(base_plan, aggregate_plan);

        IndexMap::from([
            (OUTPUT_PLAN_KEY.to_string(), (output_plan, true)),
            (MULTIPLICITY_PLAN_KEY.to_string(), (multiplicity_plan, true)),
        ])
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
        let aggregate_plan = match self.node_id.to_lp() {
            Some(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        };
        let group_col_count = aggregate_plan.group_expr.len();
        let aggregate_col_count = aggregate_plan.aggr_expr.len();

        let mut aggregate_entries = Vec::new();
        let mut passthrough_entries = Vec::new();
        let mut activator_entry = None;
        for (idx, (field, oracle)) in existing_output.tracked_oracles().into_iter().enumerate() {
            if field.name() == ACTIVATOR_COL_NAME {
                activator_entry = Some((field, oracle));
            } else if idx >= group_col_count && idx < group_col_count + aggregate_col_count {
                aggregate_entries.push((field, oracle));
            } else if idx >= group_col_count + aggregate_col_count {
                passthrough_entries.push((field, oracle));
            } else {
                // Grouping columns are re-attached from child outputs below.
            }
        }

        if !self.aggr_expr_proof_tree_roots.is_empty() {
            if aggregate_entries.len() != self.aggr_expr_proof_tree_roots.len() {
                panic!(
                    "aggregate expressions count mismatch: expected {}, found {}",
                    self.aggr_expr_proof_tree_roots.len(),
                    aggregate_entries.len()
                );
            }

            let (activator_field, activator_oracle) = activator_entry
                .as_ref()
                .unwrap_or_else(|| panic!("aggregate output missing activator column"));

            for (idx, aggr_node) in self.aggr_expr_proof_tree_roots.iter().enumerate() {
                let (agg_field, agg_oracle) = aggregate_entries
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| panic!("missing aggregate entry for {}", aggr_node.name()));

                let mut columns = IndexMap::with_capacity(2);
                columns.insert(agg_field, agg_oracle);
                columns.insert(activator_field.clone(), activator_oracle.clone());

                let agg_child_table =
                    TrackedTableOracle::new(None, columns, existing_output.log_size());

                piop_tree.add_tracked_table_oracle(
                    aggr_node.node_id(),
                    OUTPUT_PLAN_KEY.to_string(),
                    agg_child_table,
                );
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
            if combined_columns.contains_key(&field) {
                continue;
            }
            combined_columns.insert(field, oracle);
        }
        for (field, oracle) in passthrough_entries {
            if combined_columns.contains_key(&field) {
                continue;
            }
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
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let aggregate = match &self.node_id {
            NodeId::LP(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        }
        .clone();

        let mut grouping_columns: IndexMap<
            datafusion::arrow::datatypes::FieldRef,
            TrackedOracle<F, MvPCS, UvPCS>,
        > = IndexMap::new();
        let mut grouping_table_log_size: Option<usize> = None;

        let input_base_table = piop_tree
            .tracked_table_oracle(&self.input_proof_tree_root.node_id(), OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| panic!("missing output_plan table for aggregate input"));

        for group_node in &self.group_expr_proof_tree_roots {
            let table = piop_tree
                .tracked_table_oracle(&group_node.node_id(), OUTPUT_PLAN_KEY)
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

            for (field, poly) in table.tracked_oracles() {
                if field.name() == ACTIVATOR_COL_NAME {
                    continue;
                }
                grouping_columns.insert(field.clone(), poly.clone());
            }
        }

        if let Some((field, poly)) = input_base_table
            .tracked_oracles()
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
        {
            grouping_columns.insert(field, poly);
        }

        let input_grouping_table_oracle = TrackedTableOracle::new(
            None,
            grouping_columns,
            grouping_table_log_size.unwrap_or_else(|| input_base_table.log_size()),
        );

        let output_table = piop_tree
            .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| panic!("missing output_plan table for aggregate node"));
        let grouping_col_count = aggregate.group_expr.len();
        let mut output_grouping_columns = IndexMap::with_capacity(grouping_col_count);
        for (idx, (field, poly)) in output_table.tracked_oracles().iter().enumerate() {
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
        if let Some((field, poly)) = output_table
            .tracked_oracles()
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
        {
            output_grouping_columns.insert(field, poly);
        }
        let output_grouping_table_oracle =
            TrackedTableOracle::new(None, output_grouping_columns, output_table.log_size());

        let aggregate_piop_verifier_input: AggregatePIOPVerifierInput<F, MvPCS, UvPCS> =
            AggregatePIOPVerifierInput {
                aggregate,
                input_grouping_table_oracle,
                output_grouping_table_oracle,
            };
        let aggregate_piop_verifier_output =
            AggregatePIOP::verify(verifier, aggregate_piop_verifier_input)?;

        let AggregatePIOPVerifierOutput {
            grouping_multiplicty_tracked_oracle: grouping_multiplicity_oracle,
            input_folded_tracked_col_oracle,
            output_folded_tracked_col_oracle,
        } = aggregate_piop_verifier_output;
        debug_assert_eq!(
            grouping_multiplicity_oracle.log_size(),
            input_folded_tracked_col_oracle.log_size(),
            "folded input oracle log size mismatch with multiplicity"
        );
        debug_assert_eq!(
            grouping_multiplicity_oracle.log_size(),
            output_folded_tracked_col_oracle.log_size(),
            "folded output oracle log size mismatch with multiplicity"
        );
        let multiplicity_log_size = grouping_multiplicity_oracle.log_size();
        let multiplicity_field = grouping_multiplicity_field();
        let mut columns = IndexMap::new();
        columns.insert(multiplicity_field, grouping_multiplicity_oracle);
        columns.insert(
            grouping_input_folded_field(),
            input_folded_tracked_col_oracle.data_tracked_oracle(),
        );
        columns.insert(
            grouping_output_folded_field(),
            output_folded_tracked_col_oracle.data_tracked_oracle(),
        );
        let auxiliary_table = TrackedTableOracle::new(None, columns, multiplicity_log_size);
        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            "auxiliary".to_string(),
            auxiliary_table,
        );

        self.children()
            .iter()
            .try_for_each(|child| child.verify_piop(verifier, piop_tree))?;
        Ok(())
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

fn build_aggregate_hint_output_plan(
    base_plan: LogicalPlan,
    aggregate_plan: &df::Aggregate,
) -> LogicalPlan {
    const BASE_ALIAS: &str = "__dbsnark_aggr_base";
    const AGG_ALIAS: &str = "__dbsnark_aggr_values";
    const POS_COL: &str = "__dbsnark_aggr_pos";
    const RN_COL: &str = "__dbsnark_aggr_rank";
    const GROUP_EXPR_PREFIX: &str = "__dbsnark_aggr_group_expr_";

    let base_schema = base_plan.schema().clone();

    let mut projection_exprs: Vec<Expr> = base_schema
        .iter()
        .map(|(qualifier, field)| Expr::from((qualifier, field)))
        .collect();

    let group_aliases: Vec<String> = aggregate_plan
        .group_expr
        .iter()
        .enumerate()
        .map(|(idx, _)| format!("{GROUP_EXPR_PREFIX}{idx}"))
        .collect();

    for (expr, alias) in aggregate_plan.group_expr.iter().zip(group_aliases.iter()) {
        projection_exprs.push(expr.clone().alias(alias.clone()));
    }

    let base_with_group_exprs = LogicalPlanBuilder::from(base_plan)
        .project(projection_exprs)
        .expect("failed to append group expressions to aggregate base plan")
        .build()
        .expect("failed to build base plan with group expressions");

    let base_with_pos = LogicalPlanBuilder::from(base_with_group_exprs.clone())
        .window(vec![row_number().alias(POS_COL)])
        .expect("failed to append position column for aggregate plan")
        .build()
        .expect("failed to build plan with position column");

    let partition_exprs: Vec<Expr> = group_aliases
        .iter()
        .map(|alias| Expr::Column(Column::from_name(alias.clone())))
        .collect();

    let order_exprs = vec![Expr::Column(Column::from_name(POS_COL.to_string())).sort(true, false)];

    let rn_expr = row_number()
        .partition_by(partition_exprs)
        .order_by(order_exprs)
        .build()
        .expect("failed to construct row_number expression for aggregate plan")
        .alias(RN_COL);

    let base_with_rn = LogicalPlanBuilder::from(base_with_pos.clone())
        .window(vec![rn_expr])
        .expect("failed to append per-group rank column to aggregate plan")
        .build()
        .expect("failed to build plan with per-group rank column");

    let group_by_exprs_for_agg: Vec<Expr> = group_aliases
        .iter()
        .map(|alias| Expr::Column(Column::from_name(alias.clone())))
        .collect();

    let activator_filter = Expr::Column(Column::from_name(ACTIVATOR_COL_NAME.to_string()));
    let activated_base_for_agg = LogicalPlanBuilder::from(base_with_group_exprs.clone())
        .filter(activator_filter)
        .expect("failed to filter inactive rows for aggregate hint generation")
        .build()
        .expect("failed to build filtered aggregate base plan");

    let aggregate_values_plan = LogicalPlanBuilder::from(activated_base_for_agg)
        .aggregate(group_by_exprs_for_agg, aggregate_plan.aggr_expr.clone())
        .expect("failed to build aggregate plan for hint generation")
        .build()
        .expect("failed to finalize aggregate hint plan");
    let agg_has_activator = aggregate_values_plan
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);

    let base_table_ref = TableReference::bare(BASE_ALIAS);
    let agg_table_ref = TableReference::bare(AGG_ALIAS);

    let base_aliased = LogicalPlanBuilder::from(base_with_rn)
        .alias(base_table_ref.clone())
        .expect("failed to alias aggregate base plan")
        .build()
        .expect("failed to build aliased aggregate base plan");

    let agg_aliased = LogicalPlanBuilder::from(aggregate_values_plan)
        .alias(agg_table_ref.clone())
        .expect("failed to alias aggregate values plan")
        .build()
        .expect("failed to build aliased aggregate values plan");

    let left_join_cols: Vec<Column> = group_aliases
        .iter()
        .map(|alias| Column::new(Some(base_table_ref.clone()), alias.clone()))
        .collect();
    let right_join_cols: Vec<Column> = group_aliases
        .iter()
        .map(|alias| Column::new(Some(agg_table_ref.clone()), alias.clone()))
        .collect();

    let joined = LogicalPlanBuilder::from(base_aliased)
        .join(
            agg_aliased,
            JoinType::Inner,
            (left_join_cols, right_join_cols),
            None,
        )
        .expect("failed to join aggregate base with aggregate values")
        .build()
        .expect("failed to build joined aggregate hint plan");

    let pos_sort = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        POS_COL.to_string(),
    ))
    .sort(true, false);

    let sorted = LogicalPlanBuilder::from(joined)
        .sort(vec![pos_sort])
        .expect("failed to apply ordering to aggregate hint plan")
        .build()
        .expect("failed to build sorted aggregate hint plan");

    let agg_schema = aggregate_plan.schema.as_ref();
    let mut final_exprs =
        Vec::with_capacity(group_aliases.len() + aggregate_plan.aggr_expr.len() + 1);

    for (idx, alias) in group_aliases.iter().enumerate() {
        let field_name = agg_schema.field(idx).name().clone();
        final_exprs.push(
            Expr::Column(Column::new(Some(base_table_ref.clone()), alias.clone()))
                .alias(field_name),
        );
    }

    for (agg_idx, _) in aggregate_plan.aggr_expr.iter().enumerate() {
        let schema_idx = group_aliases.len() + agg_idx;
        let field_name = agg_schema.field(schema_idx).name().clone();
        final_exprs.push(
            Expr::Column(Column::new(Some(agg_table_ref.clone()), field_name.clone()))
                .alias(field_name),
        );
    }

    let rank_column = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        RN_COL.to_string(),
    ));
    let activator_column = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        ACTIVATOR_COL_NAME.to_string(),
    ));
    let output_activator_expr = if agg_has_activator {
        Expr::Column(Column::new(
            Some(agg_table_ref.clone()),
            ACTIVATOR_COL_NAME.to_string(),
        ))
    } else {
        Expr::Literal(ScalarValue::Boolean(Some(true)))
    };
    let combined_activator = Expr::BinaryExpr(datafusion_expr::expr::BinaryExpr::new(
        Box::new(activator_column),
        Operator::And,
        Box::new(output_activator_expr),
    ));
    let activator_case = Expr::Case(Case::new(
        None,
        vec![(
            Box::new(rank_column.eq(Expr::Literal(ScalarValue::UInt64(Some(1))))),
            Box::new(combined_activator),
        )],
        Some(Box::new(Expr::Literal(ScalarValue::Boolean(Some(false))))),
    ))
    .alias(ACTIVATOR_COL_NAME.to_string());
    final_exprs.push(activator_case);

    LogicalPlanBuilder::from(sorted)
        .project(final_exprs)
        .expect("failed to project final aggregate hint output")
        .build()
        .expect("failed to construct aggregate hint output plan")
}

fn build_aggregate_multiplicity_hint_plan(
    base_plan: LogicalPlan,
    aggregate_plan: &df::Aggregate,
) -> LogicalPlan {
    const BASE_ALIAS: &str = "__dbsnark_aggr_base";
    const AGG_ALIAS: &str = "__dbsnark_aggr_values";
    const POS_COL: &str = "__dbsnark_aggr_pos";
    const RN_COL: &str = "__dbsnark_aggr_rank";
    const GROUP_EXPR_PREFIX: &str = "__dbsnark_aggr_group_expr_";

    let base_schema = base_plan.schema().clone();

    let mut projection_exprs: Vec<Expr> = base_schema
        .iter()
        .map(|(qualifier, field)| Expr::from((qualifier, field)))
        .collect();

    let group_aliases: Vec<String> = aggregate_plan
        .group_expr
        .iter()
        .enumerate()
        .map(|(idx, _)| format!("{GROUP_EXPR_PREFIX}{idx}"))
        .collect();

    for (expr, alias) in aggregate_plan.group_expr.iter().zip(group_aliases.iter()) {
        projection_exprs.push(expr.clone().alias(alias.clone()));
    }

    let base_with_group_exprs = LogicalPlanBuilder::from(base_plan)
        .project(projection_exprs)
        .expect("failed to append group expressions to aggregate base plan")
        .build()
        .expect("failed to build base plan with group expressions");

    let base_with_pos = LogicalPlanBuilder::from(base_with_group_exprs.clone())
        .window(vec![row_number().alias(POS_COL)])
        .expect("failed to append position column for aggregate plan")
        .build()
        .expect("failed to build plan with position column");

    let partition_exprs: Vec<Expr> = group_aliases
        .iter()
        .map(|alias| Expr::Column(Column::from_name(alias.clone())))
        .collect();

    let order_exprs = vec![Expr::Column(Column::from_name(POS_COL.to_string())).sort(true, false)];

    let rn_expr = row_number()
        .partition_by(partition_exprs)
        .order_by(order_exprs)
        .build()
        .expect("failed to construct row_number expression for aggregate plan")
        .alias(RN_COL);

    let base_with_rn = LogicalPlanBuilder::from(base_with_pos.clone())
        .window(vec![rn_expr])
        .expect("failed to append per-group rank column to aggregate plan")
        .build()
        .expect("failed to build plan with per-group rank column");

    let group_by_exprs_for_agg: Vec<Expr> = group_aliases
        .iter()
        .map(|alias| Expr::Column(Column::from_name(alias.clone())))
        .collect();

    let activator_filter = Expr::Column(Column::from_name(ACTIVATOR_COL_NAME.to_string()));
    let activated_base_for_agg = LogicalPlanBuilder::from(base_with_group_exprs.clone())
        .filter(activator_filter)
        .expect("failed to filter inactive rows for multiplicity hint generation")
        .build()
        .expect("failed to build filtered base plan for multiplicity hint");

    let aggregate_values_plan = LogicalPlanBuilder::from(activated_base_for_agg)
        .aggregate(group_by_exprs_for_agg, vec![count_all()])
        .expect("failed to build multiplicity aggregate plan for hint generation")
        .build()
        .expect("failed to finalize multiplicity aggregate hint plan");

    let base_table_ref = TableReference::bare(BASE_ALIAS);
    let agg_table_ref = TableReference::bare(AGG_ALIAS);

    let base_aliased = LogicalPlanBuilder::from(base_with_rn)
        .alias(base_table_ref.clone())
        .expect("failed to alias aggregate base plan")
        .build()
        .expect("failed to build aliased aggregate base plan");

    let agg_aliased = LogicalPlanBuilder::from(aggregate_values_plan.clone())
        .alias(agg_table_ref.clone())
        .expect("failed to alias aggregate values plan")
        .build()
        .expect("failed to build aliased aggregate values plan");

    let left_join_cols: Vec<Column> = group_aliases
        .iter()
        .map(|alias| Column::new(Some(base_table_ref.clone()), alias.clone()))
        .collect();
    let right_join_cols: Vec<Column> = group_aliases
        .iter()
        .map(|alias| Column::new(Some(agg_table_ref.clone()), alias.clone()))
        .collect();

    let joined = LogicalPlanBuilder::from(base_aliased)
        .join(
            agg_aliased,
            JoinType::Inner,
            (left_join_cols, right_join_cols),
            None,
        )
        .expect("failed to join multiplicity aggregate base with aggregate values")
        .build()
        .expect("failed to build joined multiplicity aggregate hint plan");

    let pos_sort = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        POS_COL.to_string(),
    ))
    .sort(true, false);

    let sorted = LogicalPlanBuilder::from(joined)
        .sort(vec![pos_sort])
        .expect("failed to apply ordering to multiplicity hint plan")
        .build()
        .expect("failed to build sorted multiplicity hint plan");

    let agg_schema = aggregate_plan.schema.as_ref();
    let agg_values_schema = aggregate_values_plan.schema();
    let mut final_exprs = Vec::with_capacity(group_aliases.len() + 2);

    for (idx, alias) in group_aliases.iter().enumerate() {
        let field_name = agg_schema.field(idx).name().clone();
        final_exprs.push(
            Expr::Column(Column::new(Some(base_table_ref.clone()), alias.clone()))
                .alias(field_name),
        );
    }

    let multiplicity_field_name = agg_values_schema
        .field(group_aliases.len())
        .name()
        .clone();
    final_exprs.push(
        Expr::Column(Column::new(
            Some(agg_table_ref.clone()),
            multiplicity_field_name,
        ))
        .alias(GROUP_MULTIPLICITY_COL_NAME.to_string()),
    );

    let rank_column = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        RN_COL.to_string(),
    ));
    let activator_column = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        ACTIVATOR_COL_NAME.to_string(),
    ));
    let output_activator_expr = Expr::Literal(ScalarValue::Boolean(Some(true)));
    let combined_activator = Expr::BinaryExpr(datafusion_expr::expr::BinaryExpr::new(
        Box::new(activator_column),
        Operator::And,
        Box::new(output_activator_expr),
    ));
    let activator_case = Expr::Case(Case::new(
        None,
        vec![(
            Box::new(rank_column.eq(Expr::Literal(ScalarValue::UInt64(Some(1))))),
            Box::new(combined_activator),
        )],
        Some(Box::new(Expr::Literal(ScalarValue::Boolean(Some(false))))),
    ))
    .alias(ACTIVATOR_COL_NAME.to_string());
    final_exprs.push(activator_case);

    LogicalPlanBuilder::from(sorted)
        .project(final_exprs)
        .expect("failed to project final multiplicity hint output")
        .build()
        .expect("failed to construct multiplicity hint output plan")
}
