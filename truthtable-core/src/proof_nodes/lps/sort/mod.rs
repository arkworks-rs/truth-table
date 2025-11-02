mod hints;
#[cfg(test)]
mod tests;
use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId,
        lps::sort::hints::build_sort_hint_plans, prover::ProverNode, verifier::VerifierNode,
    },
    prover::trees::proof_tree::ProverProofTree,
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP, verifier::Verifier,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef, Schema},
    prelude::SessionContext,
};
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use ra_toolbox::lp_piop::sort_check::{SortPIOP, SortPIOPProverInput, SortPIOPVerifierInput, SortTrackedCol};
use std::sync::Arc;

const SORT_EXPRESSIONS_PLAN_KEY: &str = "sort_expressions";
const SHIFTED_SORT_EXPRESSIONS_PLAN_KEY: &str = "shifted_sort_expressions";
const TIE_INDICATOR_PLAN_KEY: &str = "tie_indicator_columns";

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
        let base_plan = self
            .input_prover_node
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .map(|hint| hint.plan().clone())
            .expect("input node missing OUTPUT_PLAN hint");

        let sort_plan = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort,
            _ => panic!("expected sort logical plan"),
        };

        hints::build_sort_hint_plans(base_plan, sort_plan)
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
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
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

        let sort_verifier_input = SortPIOPVerifierInput {
            sort: sort_plan,
            input_sort_exprs,
            output_sort_exprs,
            tie_indicator_cols,
            input_table,
            output_table,
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
