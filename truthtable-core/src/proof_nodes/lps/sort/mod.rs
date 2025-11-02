#[cfg(test)]
mod tests;

use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode,
        verifier::VerifierNode,
    },
    prover::trees::proof_tree::ProverProofTree,
    verifier::trees::proof_tree::VerifierProofTree,
};
use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, Schema},
    logical_expr::{
        self as df,
        expr_rewriter::{normalize_sorts, unnormalize_col},
    },
    prelude::SessionContext,
};
use datafusion_expr::{LogicalPlan, LogicalPlanBuilder, expr::Sort as DFSortExpr};
use indexmap::IndexMap;
use ra_toolbox::lp_piop::sort_check::{SortPIOP, SortPIOPProverInput, SortPIOPVerifierInput, SortTrackedCol, SortTrackedColOracle};
use std::sync::Arc;

const SORT_EXPRESSIONS_PLAN_KEY: &str = "sort_expressions";
const SHIFTED_SORT_EXPRESSIONS_PLAN_KEY: &str = "shifted_sort_expressions";
const TIE_INDICATOR_PLAN_KEY: &str = "tie_indicator_columns";

fn build_sort_hint_plans(
    base_plan: LogicalPlan,
    sort_plan: &datafusion_expr::logical_plan::Sort,
) -> IndexMap<String, HintGenerationPlan> {
    let normalized_sorts = normalize_sorts(sort_plan.expr.clone(), &base_plan)
        .expect("failed to normalize sort expressions for hint plan")
        .into_iter()
        .map(|sort_expr| {
            let expr = unnormalize_col(sort_expr.expr);
            DFSortExpr::new(expr, sort_expr.asc, sort_expr.nulls_first)
        })
        .collect::<Vec<_>>();

    assert!(
        !normalized_sorts.is_empty(),
        "sort hint plan missing sort expressions"
    );

    let sorted_plan = LogicalPlanBuilder::from(base_plan.clone())
        .sort_with_limit(normalized_sorts.clone(), sort_plan.fetch)
        .expect("failed to append sort for hint plan")
        .build()
        .expect("failed to build sorted hint plan");

    let projection_exprs: Vec<df::Expr> = sorted_plan
        .schema()
        .iter()
        .map(|(qualifier, field)| df::Expr::from((qualifier, field)))
        .collect();

    let sorted_projected = LogicalPlanBuilder::from(sorted_plan.clone())
        .project(projection_exprs)
        .expect("failed to project sorted columns for hint plan")
        .build()
        .expect("failed to build sorted projected hint plan");

    let sort_projection_exprs: Vec<df::Expr> = normalized_sorts
        .iter()
        .map(|sort_expr| sort_expr.expr.clone())
        .collect();

    let sort_expressions_plan = LogicalPlanBuilder::from(sorted_plan)
        .project(sort_projection_exprs)
        .expect("failed to project sort expressions for hint plan")
        .build()
        .expect("failed to build sort expressions hint plan");

    let shifted_projection_exprs: Vec<df::Expr> = sort_expressions_plan
        .schema()
        .fields()
        .iter()
        .map(|field| {
            let alias_name = format!("{}_shift", field.name());
            df::col(field.name()).alias(alias_name)
        })
        .collect();

    let shifted_sort_expressions_plan = LogicalPlanBuilder::from(sort_expressions_plan.clone())
        .project(shifted_projection_exprs)
        .expect("failed to project shifted sort expressions for hint plan")
        .build()
        .expect("failed to build shifted sort expressions hint plan");

    let mut tie_plans = None;
    let num_sort_exprs = normalized_sorts.len();
    if num_sort_exprs > 1 {
        let tie_projection_exprs: Vec<df::Expr> = (0..(num_sort_exprs - 1))
            .map(|idx| df::lit(false).alias(format!("tie_indicator_{idx}")))
            .collect();
        let tie_plan = LogicalPlanBuilder::from(sort_expressions_plan.clone())
            .project(tie_projection_exprs)
            .expect("failed to project tie indicator expressions for hint plan")
            .build()
            .expect("failed to build tie indicator hint plan");
        tie_plans = Some(tie_plan);
    }

    let mut plans = IndexMap::new();
    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_string(), sorted_projected),
    );
    plans.insert(
        SORT_EXPRESSIONS_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(
            SORT_EXPRESSIONS_PLAN_KEY.to_string(),
            sort_expressions_plan,
        ),
    );
    plans.insert(
        SHIFTED_SORT_EXPRESSIONS_PLAN_KEY.to_string(),
        HintGenerationPlan::new_virtual(
            SHIFTED_SORT_EXPRESSIONS_PLAN_KEY.to_string(),
            shifted_sort_expressions_plan,
        ),
    );
    if let Some(tie_plan) = tie_plans {
        plans.insert(
            TIE_INDICATOR_PLAN_KEY.to_string(),
            HintGenerationPlan::new_virtual(TIE_INDICATOR_PLAN_KEY.to_string(), tie_plan),
        );
    }

    plans
}

pub struct ProverSortExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

pub struct VerifierSortExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

pub struct ProverSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub sort_exprs: Vec<ProverSortExprNode<F, MvPCS, UvPCS>>,
    pub input_prover_node: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}
pub struct VerifierSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub sort_exprs: Vec<VerifierSortExprNode<F, MvPCS, UvPCS>>,
    pub input_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut children = vec![&self.input_prover_node];

        for sort_expr in &self.sort_exprs {
            children.push(&sort_expr.expr);
        }

        children
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let base_plan = &self
            .input_prover_node
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .map(|hint| hint.plan().clone())
            .expect("input node missing OUTPUT_PLAN hint");

        let sort_plan = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort,
            _ => panic!("expected sort logical plan"),
        };

        build_sort_hint_plans(base_plan.clone(), sort_plan)
    }

    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let sort_plan = match &plan {
            LogicalPlan::Sort(sort) => sort,
            _ => panic!("expected sort logical plan"),
        };

        let node_id = NodeId::LP(plan.clone());

        let input_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            sort_plan.input.as_ref(),
            &node_id,
        )
        .root();

        let sort_exprs = sort_plan
            .expr
            .iter()
            .map(|sort_expr| {
                let expr_node = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    sort_expr.expr.clone(),
                    &node_id,
                )
                .root();

                ProverSortExprNode {
                    expr: expr_node,
                    asc: sort_expr.asc,
                    nulls_first: sort_expr.nulls_first,
                }
            })
            .collect();

        Self {
            sort_exprs,
            input_prover_node,
            node_id,
        }
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        self.input_prover_node.clone()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        use ark_piop::arithmetic::mat_poly::mle::MLE;

        let Some(sort_exprs_table) = piop_tree
            .tracked_table(&self.node_id, SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
        else {
            return;
        };

        let log_size = sort_exprs_table.log_size();
        let mut data_columns = Vec::new();
        let mut activator_entry = None;
        for (field, poly) in sort_exprs_table.tracked_polys() {
            if field.name() == ACTIVATOR_COL_NAME {
                activator_entry = Some((field, poly));
            } else {
                data_columns.push((field, poly));
            }
        }

        if data_columns.is_empty() {
            return;
        }

        let table_activator = sort_exprs_table.activator_tracked_poly();
        let (activator_vals, shifted_activator_vals) = if let Some(poly) = table_activator.as_ref()
        {
            let vals = poly.evaluations();
            let mut shifted = vals.clone();
            shifted.rotate_left(1);
            (Some(vals), Some(shifted))
        } else {
            (None, None)
        };

        let mut shifted_columns = IndexMap::new();
        let mut shifted_schema_fields = Vec::new();

        for (field, poly) in &data_columns {
            let tracked_col =
                TrackedCol::new(poly.clone(), table_activator.clone(), Some(field.clone()));
            let shifted_col = circular_shift_tracked_col(prover, &tracked_col)
                .expect("failed to build shifted sort expression column");

            let alias_name = format!("{}_shift", field.name());
            let alias_field = Arc::new(Field::new(
                alias_name,
                field.data_type().clone(),
                field.is_nullable(),
            ));
            shifted_schema_fields.push(alias_field.as_ref().clone());
            shifted_columns.insert(alias_field, shifted_col.data_tracked_poly());
        }

        if let Some((field, poly)) = activator_entry.clone() {
            shifted_schema_fields.push(field.as_ref().clone());
            shifted_columns.insert(field, poly);
        }

        let shifted_table = TrackedTable::new(
            Some(Schema::new(shifted_schema_fields)),
            shifted_columns,
            log_size,
        );

        piop_tree.add_table(
            self.node_id.clone(),
            SHIFTED_SORT_EXPRESSIONS_PLAN_KEY.to_string(),
            shifted_table,
        );

        if data_columns.len() > 1 {
            let mut tie_columns = IndexMap::new();
            let mut tie_schema_fields = Vec::new();
            let mut cumulative_ties = vec![F::one(); 1 << log_size];

            for (idx, (_field, poly)) in data_columns.iter().enumerate() {
                let mut values = poly.evaluations();
                let mut shifted_values = values.clone();
                shifted_values.rotate_left(1);

                for row in 0..values.len() {
                    let mut eq = if values[row] == shifted_values[row] {
                        F::one()
                    } else {
                        F::zero()
                    };

                    if let (Some(activator), Some(shifted_activator)) =
                        (&activator_vals, &shifted_activator_vals)
                    {
                        eq *= activator[row];
                        eq *= shifted_activator[row];
                    }

                    if idx == 0 {
                        cumulative_ties[row] = eq;
                    } else {
                        cumulative_ties[row] *= eq;
                    }
                }

                if idx < data_columns.len() - 1 {
                    let field_name = format!("tie_indicator_{idx}");
                    let tie_field = Arc::new(Field::new(field_name, DataType::Boolean, false));
                    tie_schema_fields.push(tie_field.as_ref().clone());
                    let tie_mle = MLE::from_evaluations_vec(log_size, cumulative_ties.clone());
                    let tie_poly = prover
                        .track_and_commit_mat_mv_poly(&tie_mle)
                        .expect("failed to build tie indicator column");
                    tie_columns.insert(tie_field, tie_poly);
                }
            }

            if !tie_columns.is_empty() {
                let tie_table =
                    TrackedTable::new(Some(Schema::new(tie_schema_fields)), tie_columns, log_size);
                piop_tree.add_table(
                    self.node_id.clone(),
                    TIE_INDICATOR_PLAN_KEY.to_string(),
                    tie_table,
                );
            }
        }
    }

    fn prove_piop(
        &self,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let sort_plan = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort.clone(),
            _ => panic!("expected sort logical plan"),
        };

        let input_table = piop_tree
            .tracked_table(&self.input_prover_node.node_id(), OUTPUT_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort input node {}",
                    OUTPUT_PLAN_KEY,
                    self.input_prover_node.node_id()
                )
            });

        let output_table = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    OUTPUT_PLAN_KEY, self.node_id
                )
            });

        let output_sort_exprs_table = piop_tree
            .tracked_table(&self.node_id, SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });

        let mut input_sort_exprs = Vec::with_capacity(self.sort_exprs.len());
        for sort_expr_node in &self.sort_exprs {
            let expr_table = piop_tree
                .tracked_table(&sort_expr_node.expr.node_id(), OUTPUT_PLAN_KEY)
                .unwrap_or_else(|| {
                    panic!(
                        "missing {} table for sort expression node {}",
                        OUTPUT_PLAN_KEY,
                        sort_expr_node.expr.node_id()
                    )
                });

            let mut data_cols = expr_table
                .tracked_polys()
                .into_iter()
                .filter(|(field, _)| field.name() != ACTIVATOR_COL_NAME);

            let (field, poly) = data_cols.next().unwrap_or_else(|| {
                panic!(
                    "sort expression node {} produced no data column",
                    sort_expr_node.expr.node_id()
                )
            });
            if data_cols.next().is_some() {
                panic!(
                    "sort expression node {} produced more than one data column",
                    sort_expr_node.expr.node_id()
                );
            }

            let tracked_col = TrackedCol::new(
                poly,
                expr_table.activator_tracked_poly(),
                Some(field.clone()),
            );
            let shifted_col = circular_shift_tracked_col(prover, &tracked_col)?;

            input_sort_exprs.push(SortTrackedCol {
                expr: tracked_col,
                shifted_expr: shifted_col,
                asc: sort_expr_node.asc,
                nulls_first: sort_expr_node.nulls_first,
            });
        }

        let output_activator = output_sort_exprs_table.activator_tracked_poly();
        let output_expr_cols = output_sort_exprs_table
            .tracked_polys()
            .into_iter()
            .filter(|(field, _)| field.name() != ACTIVATOR_COL_NAME)
            .map(|(field, poly)| TrackedCol::new(poly, output_activator.clone(), Some(field)))
            .collect::<Vec<_>>();

        if output_expr_cols.len() != self.sort_exprs.len() {
            panic!(
                "expected {} sort expression columns in output but found {}",
                self.sort_exprs.len(),
                output_expr_cols.len()
            );
        }

        let shifted_sort_exprs_table = piop_tree
            .tracked_table(&self.node_id, SHIFTED_SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    SHIFTED_SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });
        let shifted_expr_cols = shifted_sort_exprs_table
            .tracked_polys()
            .into_iter()
            .filter(|(field, _)| field.name() != ACTIVATOR_COL_NAME)
            .map(|(field, poly)| {
                TrackedCol::new(
                    poly,
                    shifted_sort_exprs_table.activator_tracked_poly(),
                    Some(field),
                )
            })
            .collect::<Vec<_>>();

        if shifted_expr_cols.len() != self.sort_exprs.len() {
            panic!(
                "expected {} shifted sort expression columns in output but found {}",
                self.sort_exprs.len(),
                shifted_expr_cols.len()
            );
        }

        let tie_indicator_cols = piop_tree
            .tracked_table(&self.node_id, TIE_INDICATOR_PLAN_KEY)
            .map(|table| {
                table
                    .tracked_polys()
                    .into_iter()
                    .map(|(field, poly)| TrackedCol::new(poly, None, Some(field)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let output_sort_exprs = self
            .sort_exprs
            .iter()
            .zip(
                output_expr_cols
                    .into_iter()
                    .zip(shifted_expr_cols.into_iter()),
            )
            .map(|(sort_expr_node, (expr_col, shifted_col))| SortTrackedCol {
                expr: expr_col,
                shifted_expr: shifted_col,
                asc: sort_expr_node.asc,
                nulls_first: sort_expr_node.nulls_first,
            })
            .collect::<Vec<_>>();

        let sort_prover_input = SortPIOPProverInput {
            sort: sort_plan,
            input_sort_exprs,
            output_sort_exprs,
            tie_indicator_cols,
            input_table,
            output_table,
        };
        SortPIOP::prove(prover, sort_prover_input)?;

        Ok(())
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut children = vec![&self.input_verifier_node];

        for sort_expr in &self.sort_exprs {
            children.push(&sort_expr.expr);
        }
        children
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let input_node = proof_tree
            .node(&self.input_verifier_node.node_id())
            .expect("missing input node for sort");
        let base_plan = input_node
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .map(|hint| hint.plan().clone())
            .expect("input node missing OUTPUT_PLAN hint");

        let sort_plan = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort,
            _ => panic!("expected sort logical plan"),
        };

        build_sort_hint_plans(base_plan, sort_plan)
    }

    fn from_lp(
        ctx: &SessionContext,
        verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let sort_plan = match &plan {
            LogicalPlan::Sort(sort) => sort,
            _ => panic!("expected sort logical plan"),
        };

        let node_id = NodeId::LP(plan.clone());

        let input_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            verifier_ctx.clone(),
            sort_plan.input.as_ref(),
            &node_id,
        )
        .root();

        let sort_exprs = sort_plan
            .expr
            .iter()
            .map(|sort_expr| {
                let expr_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    sort_expr.expr.clone(),
                    &node_id,
                )
                .root();

                VerifierSortExprNode {
                    expr: expr_node,
                    asc: sort_expr.asc,
                    nulls_first: sort_expr.nulls_first,
                }
            })
            .collect();

        Self {
            sort_exprs,
            input_verifier_node,
            node_id,
        }
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn verify_piop(
        &self,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let sort_plan = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort.clone(),
            _ => panic!("expected sort logical plan"),
        };

        let input_table_oracle = piop_tree
            .tracked_table_oracle(&self.input_verifier_node.node_id(), OUTPUT_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort input node {}",
                    OUTPUT_PLAN_KEY,
                    self.input_verifier_node.node_id()
                )
            });

        let output_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    OUTPUT_PLAN_KEY, self.node_id
                )
            });

        let output_sort_exprs_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id, SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });

        let shifted_sort_exprs_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id, SHIFTED_SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    SHIFTED_SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });

        let tie_indicator_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id, TIE_INDICATOR_PLAN_KEY)
            .cloned();

        let input_sort_exprs = self
            .sort_exprs
            .iter()
            .map(|sort_expr_node| {
                let expr_table = piop_tree
                    .tracked_table_oracle(&sort_expr_node.expr.node_id(), OUTPUT_PLAN_KEY)
                    .cloned()
                    .unwrap_or_else(|| {
                        panic!(
                            "missing {} table for sort expression node {}",
                            OUTPUT_PLAN_KEY,
                            sort_expr_node.expr.node_id()
                        )
                    });

                let mut data_cols = expr_table
                    .tracked_oracles()
                    .into_iter()
                    .filter(|(field, _)| field.name() != ACTIVATOR_COL_NAME);

                let (field, oracle) = data_cols.next().unwrap_or_else(|| {
                    panic!(
                        "sort expression node {} produced no data column oracle",
                        sort_expr_node.expr.node_id()
                    )
                });
                if data_cols.next().is_some() {
                    panic!(
                        "sort expression node {} produced more than one data column oracle",
                        sort_expr_node.expr.node_id()
                    );
                }

                let expr_col = TrackedColOracle::new(
                    oracle,
                    expr_table.activator_tracked_poly(),
                    Some(field.clone()),
                );

                SortTrackedColOracle {
                    expr: expr_col.clone(),
                    shifted_expr: expr_col,
                    asc: sort_expr_node.asc,
                    nulls_first: sort_expr_node.nulls_first,
                }
            })
            .collect::<Vec<_>>();

        let output_activator_oracle = output_sort_exprs_table_oracle.activator_tracked_poly();
        let mut output_expr_col_oracles = output_sort_exprs_table_oracle
            .tracked_oracles()
            .into_iter()
            .filter(|(field, _)| field.name() != ACTIVATOR_COL_NAME)
            .map(|(field, oracle)| {
                TrackedColOracle::new(oracle, output_activator_oracle.clone(), Some(field))
            })
            .collect::<Vec<_>>();

        if output_expr_col_oracles.len() != self.sort_exprs.len() {
            panic!(
                "expected {} sort expression column oracles in output but found {}",
                self.sort_exprs.len(),
                output_expr_col_oracles.len()
            );
        }

        let shifted_activator_oracle = shifted_sort_exprs_table_oracle.activator_tracked_poly();
        let mut shifted_expr_col_oracles = shifted_sort_exprs_table_oracle
            .tracked_oracles()
            .into_iter()
            .filter(|(field, _)| field.name() != ACTIVATOR_COL_NAME)
            .map(|(field, oracle)| {
                TrackedColOracle::new(oracle, shifted_activator_oracle.clone(), Some(field))
            })
            .collect::<Vec<_>>();

        if shifted_expr_col_oracles.len() != self.sort_exprs.len() {
            panic!(
                "expected {} shifted sort expression column oracles in output but found {}",
                self.sort_exprs.len(),
                shifted_expr_col_oracles.len()
            );
        }

        let output_sort_exprs = self
            .sort_exprs
            .iter()
            .zip(
                output_expr_col_oracles
                    .drain(..)
                    .zip(shifted_expr_col_oracles.drain(..)),
            )
            .map(
                |(sort_expr_node, (expr_col, shifted_col))| SortTrackedColOracle {
                    expr: expr_col,
                    shifted_expr: shifted_col,
                    asc: sort_expr_node.asc,
                    nulls_first: sort_expr_node.nulls_first,
                },
            )
            .collect::<Vec<_>>();

        let tie_indicator_cols = tie_indicator_table_oracle
            .map(|table| {
                table
                    .tracked_oracles()
                    .into_iter()
                    .map(|(field, oracle)| TrackedColOracle::new(oracle, None, Some(field)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let sort_verifier_input = SortPIOPVerifierInput {
            sort: sort_plan,
            input_sort_exprs,
            output_sort_exprs,
            tie_indicator_cols,
            input_table: input_table_oracle,
            output_table: output_table_oracle,
        };

        SortPIOP::verify(verifier, sort_verifier_input)?;

        Ok(())
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        self.input_verifier_node.clone()
    }
}

fn circular_shift_tracked_col<F, MvPCS, UvPCS>(
    prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    col: &TrackedCol<F, MvPCS, UvPCS>,
) -> SnarkResult<TrackedCol<F, MvPCS, UvPCS>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    use ark_piop::arithmetic::mat_poly::mle::MLE;

    let mut shifted_evals = col.data_tracked_poly().evaluations();
    if !shifted_evals.is_empty() {
        shifted_evals.rotate_left(1);
    }
    let shifted_mle = MLE::from_evaluations_vec(col.log_size(), shifted_evals);
    let shifted_poly = prover.track_and_commit_mat_mv_poly(&shifted_mle)?;
    Ok(TrackedCol::new(
        shifted_poly,
        col.activator_tracked_poly(),
        col.field_ref(),
    ))
}
