mod hints;
use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode,
        verifier::VerifierNode,
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
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef, Schema, SchemaRef},
    common::Statistics,
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use indexmap::IndexMap;
use ra_toolbox::lp_piop::aggregate_check::{
    AggregatePIOP, AggregatePIOPProverInput, AggregatePIOPProverOutput, AggregatePIOPVerifierInput,
    AggregatePIOPVerifierOutput,
};
use std::sync::Arc;

pub(crate) const GROUP_MULTIPLICITY_COL_NAME: &str = "__truthtable_group_multiplicity";
pub(crate) const GROUP_INPUT_FOLDED_COL_NAME: &str = "__truthtable_group_input_folded";
pub(crate) const GROUP_OUTPUT_FOLDED_COL_NAME: &str = "__truthtable_group_output_folded";

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
                let is_valid_aggregate = match expr {
                    Expr::AggregateFunction(_) => true,
                    Expr::Alias(alias) => matches!(alias.expr.as_ref(), Expr::AggregateFunction(_)),
                    _ => false,
                };
                if !is_valid_aggregate {
                    panic!(
                        "expected aggregate expression to be AggregateFunction (optionally wrapped in an alias), got {expr}"
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

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        let mut labels = Vec::new();
        labels.push(Some("input".to_string()));
        for (idx, _) in self.group_expr_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("group_expr[{idx}]")));
        }
        for (idx, _) in self.aggr_expr_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("agg_expr[{idx}]")));
        }
        labels
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let aggregate_plan = match &self.node_id {
            NodeId::LP(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        };

        let base_plan = proof_tree
            .node(&self.input_proof_tree_root.node_id())
            .and_then(|node| {
                node.hint_generation_plans(proof_tree)
                    .get(OUTPUT_PLAN_KEY)
                    .map(|hint| hint.plan().clone())
            })
            .expect("aggregate input missing OUTPUT_PLAN hint");

        hints::build_aggregate_hint_generation_plans(base_plan, aggregate_plan)
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
        // First get the actual aggregate logical plan
        let aggregate_plan = match self.node_id.to_lp() {
            Some(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        };

        // Fetch the current output table tracked by this aggregate node
        // This should contain only the materialized columns; i.e. the new activator and
        // the aggregate expression columns
        // It remains to attach the grouping expression columns at the front
        let Some(existing_materialized_output_table) = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
        else {
            panic!("missing output plan table for the current aggregate node");
        };
        // Separate aggregate value columns and the activator from the current output
        // table.
        let group_col_count = aggregate_plan.group_expr.len();
        let aggregate_col_count = aggregate_plan.aggr_expr.len();
        let agg_schema = aggregate_plan.schema.as_ref();
        let aggr_field_names: Vec<_> = (0..aggregate_col_count)
            .map(|idx| agg_schema.field(group_col_count + idx).name().clone())
            .collect();

        let mut aggregate_entries: IndexMap<String, (FieldRef, TrackedPoly<F, MvPCS, UvPCS>)> =
            IndexMap::with_capacity(aggregate_col_count);
        let mut activator_entry = None;
        for (field, poly) in existing_materialized_output_table.tracked_polys() {
            if field.name() == ACTIVATOR_COL_NAME {
                activator_entry = Some((field.clone(), poly.clone()));
            } else if aggr_field_names.iter().any(|name| name == field.name()) {
                aggregate_entries.insert(field.name().clone(), (field.clone(), poly.clone()));
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
                let field_name = &aggr_field_names[idx];
                let (agg_field, agg_poly) = aggregate_entries
                    .get(field_name)
                    .cloned()
                    .unwrap_or_else(|| panic!("missing aggregate entry for {}", aggr_node.name()));

                let mut columns = IndexMap::with_capacity(2);
                columns.insert(agg_field, agg_poly);
                columns.insert(activator_field.clone(), activator_poly.clone());

                let agg_child_table =
                    TrackedTable::new(None, columns, existing_materialized_output_table.log_size());

                piop_tree.add_table(
                    aggr_node.node_id(),
                    OUTPUT_PLAN_KEY.to_string(),
                    agg_child_table,
                );
            }
        }

        // Rebuild the output table so grouping columns, aggregate columns and the
        // activator are materialized on this node.
        let mut group_entries: Vec<(FieldRef, TrackedPoly<F, MvPCS, UvPCS>)> =
            Vec::with_capacity(group_col_count);
        for (_idx, group_node) in self.group_expr_proof_tree_roots.iter().enumerate() {
            let group_table = piop_tree
                .tracked_table(&group_node.node_id(), OUTPUT_PLAN_KEY)
                .unwrap_or_else(|| {
                    panic!(
                        "missing output_plan table for group expr {}",
                        group_node.name()
                    )
                });
            assert_eq!(
                group_table.log_size(),
                existing_materialized_output_table.log_size(),
                "group expression table log size mismatch for aggregate output"
            );

            let (field_ref, group_poly) = group_table
                .tracked_polys()
                .iter()
                .find_map(|(field, poly)| {
                    (field.name() != ACTIVATOR_COL_NAME).then(|| (field.clone(), poly.clone()))
                })
                .unwrap_or_else(|| {
                    panic!(
                        "group expr {} did not produce a data column",
                        group_node.name()
                    )
                });

            group_entries.push((field_ref, group_poly));
        }

        let mut combined_columns = IndexMap::with_capacity(
            group_entries.len() + aggregate_entries.len() + usize::from(activator_entry.is_some()),
        );
        for (field, poly) in group_entries {
            combined_columns.insert(field, poly);
        }
        for field_name in &aggr_field_names {
            if let Some((field, poly)) = aggregate_entries.get(field_name) {
                combined_columns.insert(field.clone(), poly.clone());
            }
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
            existing_materialized_output_table.log_size(),
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
            FieldRef,
            ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>,
        > = IndexMap::new();
        let mut output_group_entries = Vec::with_capacity(self.group_expr_proof_tree_roots.len());
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

            let mut captured_group = false;
            for (field, poly) in table.tracked_polys() {
                if field.name() == ACTIVATOR_COL_NAME {
                    continue;
                }
                grouping_columns.insert(field.clone(), poly.clone());
                if !captured_group {
                    output_group_entries.push((field.clone(), poly.clone()));
                    captured_group = true;
                }
            }
        }

        assert_eq!(
            output_group_entries.len(),
            self.group_expr_proof_tree_roots.len(),
            "group expression outputs missing for aggregate node",
        );

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
        let mut output_grouping_columns = IndexMap::with_capacity(output_group_entries.len() + 1);
        for (field, poly) in output_group_entries {
            output_grouping_columns.insert(field, poly);
        }
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
                aggregate: aggregate.clone(),
                input_grouping_table,
                output_grouping_table,
            };
        let aggregate_piop_prover_output =
            AggregatePIOP::prove(prover, aggregate_piop_prover_input)?;
        let AggregatePIOPProverOutput {
            input_folded_tracked_col,
            output_folded_tracked_col,
            multiplicity_poly,
        } = aggregate_piop_prover_output;

        debug_assert_eq!(
            multiplicity_poly.log_size(),
            input_folded_tracked_col.log_size(),
            "folded input column log size mismatch with multiplicity"
        );
        debug_assert_eq!(
            multiplicity_poly.log_size(),
            output_folded_tracked_col.log_size(),
            "folded output column log size mismatch with multiplicity"
        );
        let multiplicity_log_size = multiplicity_poly.log_size();
        let multiplicity_field = grouping_multiplicity_field();
        let mut auxiliary_out_columns = IndexMap::new();
        let mut auxiliary_in_columns = IndexMap::new();
        auxiliary_in_columns.insert(
            grouping_input_folded_field(),
            input_folded_tracked_col.data_tracked_poly(),
        );
        if input_folded_tracked_col.activator_tracked_poly().is_some() {
            auxiliary_in_columns.insert(
                Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Binary, true)),
                input_folded_tracked_col.activator_tracked_poly().unwrap(),
            );
        }
        auxiliary_out_columns.insert(multiplicity_field, multiplicity_poly);
        auxiliary_out_columns.insert(
            grouping_output_folded_field(),
            output_folded_tracked_col.data_tracked_poly(),
        );
        if output_folded_tracked_col.activator_tracked_poly().is_some() {
            auxiliary_out_columns.insert(
                Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Binary, true)),
                output_folded_tracked_col.activator_tracked_poly().unwrap(),
            );
        }
        // Building the auxiliary tables
        let auxiliary_in_table =
            TrackedTable::new(None, auxiliary_in_columns, multiplicity_log_size);
        let auxiliary_out_table =
            TrackedTable::new(None, auxiliary_out_columns, multiplicity_log_size);
        // Adding the auxiliary tables to the piop tree
        piop_tree.add_table(
            self.node_id.clone(),
            "auxiliary_in".to_string(),
            auxiliary_in_table,
        );
        piop_tree.add_table(
            self.node_id.clone(),
            "auxiliary_out".to_string(),
            auxiliary_out_table,
        );
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
            let is_valid_aggregate = match expr {
                Expr::AggregateFunction(_) => true,
                Expr::Alias(alias) => matches!(alias.expr.as_ref(), Expr::AggregateFunction(_)),
                _ => false,
            };

            if !is_valid_aggregate {
                panic!(
                    "expected aggregate expression to be AggregateFunction (optionally wrapped in an alias), got {expr}"
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

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        let mut labels = Vec::new();
        labels.push(Some("input".to_string()));
        for (idx, _) in self.group_expr_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("group_expr[{idx}]")));
        }
        for (idx, _) in self.aggr_expr_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("agg_expr[{idx}]")));
        }
        labels
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let aggregate_plan = match &self.node_id {
            NodeId::LP(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        };

        let base_plan = proof_tree
            .node(&self.input_proof_tree_root.node_id())
            .and_then(|node| {
                node.hint_generation_plans(proof_tree)
                    .get(OUTPUT_PLAN_KEY)
                    .map(|hint| hint.plan().clone())
            })
            .expect("missing aggregate input output plan");

        hints::build_aggregate_hint_generation_plans(base_plan, aggregate_plan)
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

        let agg_schema = aggregate_plan.schema.as_ref();
        let aggr_field_names: Vec<_> = (0..aggregate_col_count)
            .map(|idx| agg_schema.field(group_col_count + idx).name().clone())
            .collect();

        let mut aggregate_entries: IndexMap<String, (Arc<Field>, TrackedOracle<F, MvPCS, UvPCS>)> =
            IndexMap::with_capacity(aggregate_col_count);
        let mut activator_entry = None;
        for (field, oracle) in existing_output.tracked_oracles() {
            if field.name() == ACTIVATOR_COL_NAME {
                activator_entry = Some((field.clone(), oracle.clone()));
            } else if aggr_field_names.iter().any(|name| name == field.name()) {
                aggregate_entries.insert(field.name().clone(), (field.clone(), oracle.clone()));
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
                let field_name = &aggr_field_names[idx];
                let (agg_field, agg_oracle) = aggregate_entries
                    .get(field_name)
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

        let mut group_entries: Vec<(FieldRef, TrackedOracle<F, MvPCS, UvPCS>)> =
            Vec::with_capacity(group_col_count);
        for (_idx, group_node) in self.group_expr_proof_tree_roots.iter().enumerate() {
            let group_table = piop_tree
                .tracked_table_oracle(&group_node.node_id(), OUTPUT_PLAN_KEY)
                .unwrap_or_else(|| {
                    panic!(
                        "missing output_plan table for group expr {}",
                        group_node.name()
                    )
                });
            assert_eq!(
                group_table.log_size(),
                existing_output.log_size(),
                "group expression table log size mismatch for aggregate output"
            );

            let (field_ref, group_oracle) = group_table
                .tracked_oracles()
                .iter()
                .find_map(|(field, oracle)| {
                    (field.name() != ACTIVATOR_COL_NAME).then(|| (field.clone(), oracle.clone()))
                })
                .unwrap_or_else(|| {
                    panic!(
                        "group expr {} did not produce a data column",
                        group_node.name()
                    )
                });

            group_entries.push((field_ref, group_oracle));
        }

        let mut combined_columns = IndexMap::with_capacity(
            group_entries.len() + aggregate_entries.len() + usize::from(activator_entry.is_some()),
        );
        for (field, oracle) in group_entries {
            combined_columns.insert(field, oracle);
        }
        for field_name in &aggr_field_names {
            if let Some((field, oracle)) = aggregate_entries.get(field_name) {
                combined_columns.insert(field.clone(), oracle.clone());
            }
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

        let mut grouping_columns: IndexMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>> =
            IndexMap::new();
        let mut output_group_entries = Vec::with_capacity(self.group_expr_proof_tree_roots.len());
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

            let mut captured_group = false;
            for (field, poly) in table.tracked_oracles() {
                if field.name() == ACTIVATOR_COL_NAME {
                    continue;
                }
                grouping_columns.insert(field.clone(), poly.clone());
                if !captured_group {
                    output_group_entries.push((field.clone(), poly.clone()));
                    captured_group = true;
                }
            }
        }

        assert_eq!(
            output_group_entries.len(),
            self.group_expr_proof_tree_roots.len(),
            "group expression outputs missing for aggregate node",
        );

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
        let mut output_grouping_columns = IndexMap::with_capacity(output_group_entries.len() + 1);
        for (field, oracle) in output_group_entries {
            output_grouping_columns.insert(field, oracle);
        }
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
                aggregate: aggregate.clone(),
                input_grouping_table_oracle,
                output_grouping_table_oracle,
            };
        let aggregate_piop_verifier_output =
            AggregatePIOP::verify(verifier, aggregate_piop_verifier_input)?;

        let AggregatePIOPVerifierOutput {
            input_folded_tracked_col_oracle,
            output_folded_tracked_col_oracle,
            multiplicity_oracle,
        } = aggregate_piop_verifier_output;
        debug_assert_eq!(
            multiplicity_oracle.log_size(),
            input_folded_tracked_col_oracle.log_size(),
            "folded input oracle log size mismatch with multiplicity"
        );
        debug_assert_eq!(
            multiplicity_oracle.log_size(),
            output_folded_tracked_col_oracle.log_size(),
            "folded output oracle log size mismatch with multiplicity"
        );
        let multiplicity_log_size = multiplicity_oracle.log_size();
        let multiplicity_field = grouping_multiplicity_field();
        let mut auxiliary_out_columns = IndexMap::new();
        let mut auxiliary_in_columns = IndexMap::new();
        auxiliary_in_columns.insert(
            grouping_input_folded_field(),
            input_folded_tracked_col_oracle.data_tracked_oracle(),
        );
        if let Some(activator) = input_folded_tracked_col_oracle.activator_tracked_oracle() {
            auxiliary_in_columns.insert(
                Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Binary, true)),
                activator,
            );
        }
        auxiliary_out_columns.insert(multiplicity_field, multiplicity_oracle);
        auxiliary_out_columns.insert(
            grouping_output_folded_field(),
            output_folded_tracked_col_oracle.data_tracked_oracle(),
        );
        if let Some(activator) = output_folded_tracked_col_oracle.activator_tracked_oracle() {
            auxiliary_out_columns.insert(
                Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Binary, true)),
                activator,
            );
        }
        let auxiliary_in_table =
            TrackedTableOracle::new(None, auxiliary_in_columns, multiplicity_log_size);
        let auxiliary_out_table =
            TrackedTableOracle::new(None, auxiliary_out_columns, multiplicity_log_size);
        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            "auxiliary_in".to_string(),
            auxiliary_in_table,
        );
        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            "auxiliary_out".to_string(),
            auxiliary_out_table,
        );
        Ok(())
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        self.input_proof_tree_root.clone()
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
