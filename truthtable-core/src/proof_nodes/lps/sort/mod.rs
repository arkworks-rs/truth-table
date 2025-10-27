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
use arithmetic::ACTIVATOR_COL_NAME;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
};
use datafusion::{
    logical_expr::{
        self as df,
        expr_rewriter::{normalize_sorts, unnormalize_col},
    },
    prelude::SessionContext,
};
use datafusion_expr::{LogicalPlan, LogicalPlanBuilder, expr::Sort as DFSortExpr};
use indexmap::IndexMap;
use ra_toolbox::lp_piop::sort_check::{
    SortPIOP, SortPIOPProverInput, SortPIOPVerifierInput, SortTrackedCol, SortTrackedColOracle,
};
use std::sync::Arc;

const SORT_EXPRESSIONS_PLAN_KEY: &str = "sort_expressions";

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
        let input_node = proof_tree
            .node(&self.input_prover_node.node_id())
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
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
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
            .expect("missing sort input tracked table");

        let output_table = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
            .expect("missing sort output tracked table");

        let input_sort_exprs: Vec<SortTrackedCol<F, MvPCS, UvPCS>> = self
            .sort_exprs
            .iter()
            .map(|sort_expr| {
                let table = piop_tree
                    .tracked_table(&sort_expr.expr.node_id(), OUTPUT_PLAN_KEY)
                    .expect("missing tracked output for sort child expression");
                let expr_col = table
                    .tracked_polys_iter()
                    .enumerate()
                    .find_map(|(idx, (field, _))| {
                        (field.name() != ACTIVATOR_COL_NAME).then(|| table.tracked_col_by_ind(idx))
                    })
                    .expect("sort expression output missing data column");
                SortTrackedCol {
                    expr: expr_col,
                    asc: sort_expr.asc,
                    nulls_first: sort_expr.nulls_first,
                }
            })
            .collect();

        let output_sort_table = piop_tree
            .tracked_table(&self.node_id, SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .expect("missing materialized sort expressions table");

        let data_col_indices: Vec<usize> = output_sort_table
            .tracked_polys_iter()
            .enumerate()
            .filter_map(|(idx, (field, _))| (field.name() != ACTIVATOR_COL_NAME).then_some(idx))
            .collect();

        assert_eq!(
            data_col_indices.len(),
            self.sort_exprs.len(),
            "materialized sort expressions must match sort keys"
        );

        let output_sort_exprs: Vec<SortTrackedCol<F, MvPCS, UvPCS>> = self
            .sort_exprs
            .iter()
            .enumerate()
            .map(|(idx, sort_expr)| {
                let col_idx = data_col_indices[idx];
                SortTrackedCol {
                    expr: output_sort_table.tracked_col_by_ind(col_idx),
                    asc: sort_expr.asc,
                    nulls_first: sort_expr.nulls_first,
                }
            })
            .collect();

        let prover_input = SortPIOPProverInput {
            sort: sort_plan,
            input_sort_exprs,
            output_sort_exprs,
            input_table,
            output_table,
        };

        SortPIOP::<F, MvPCS, UvPCS>::prove(prover, prover_input)?;

        self.children()
            .iter()
            .try_for_each(|child| child.prove_piop(prover, piop_tree))?;

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

    fn add_virtual_witness(
        &self,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
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

        let input_table = piop_tree
            .tracked_table_oracle(&self.input_verifier_node.node_id(), OUTPUT_PLAN_KEY)
            .cloned()
            .expect("missing sort input tracked table oracle");

        let output_table = piop_tree
            .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
            .expect("missing sort output tracked table oracle");

        let input_sort_exprs: Vec<SortTrackedColOracle<F, MvPCS, UvPCS>> = self
            .sort_exprs
            .iter()
            .map(|sort_expr| {
                let table = piop_tree
                    .tracked_table_oracle(&sort_expr.expr.node_id(), OUTPUT_PLAN_KEY)
                    .expect("missing tracked output oracle for sort child expression");

                let data_col_idx = table
                    .tracked_oracles()
                    .keys()
                    .enumerate()
                    .find_map(|(idx, field)| (field.name() != ACTIVATOR_COL_NAME).then_some(idx))
                    .expect("sort expression oracle missing data column");

                SortTrackedColOracle {
                    expr: table.tracked_col_oracle_by_ind(data_col_idx),
                    asc: sort_expr.asc,
                    nulls_first: sort_expr.nulls_first,
                }
            })
            .collect();

        let output_sort_table = piop_tree
            .tracked_table_oracle(&self.node_id, SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .expect("missing materialized sort expression oracles");

        let data_col_indices: Vec<usize> = output_sort_table
            .tracked_oracles()
            .keys()
            .enumerate()
            .filter_map(|(idx, field)| (field.name() != ACTIVATOR_COL_NAME).then_some(idx))
            .collect();

        assert_eq!(
            data_col_indices.len(),
            self.sort_exprs.len(),
            "materialized sort expression oracles must match sort keys"
        );

        let output_sort_exprs: Vec<SortTrackedColOracle<F, MvPCS, UvPCS>> = self
            .sort_exprs
            .iter()
            .enumerate()
            .map(|(idx, sort_expr)| {
                let col_idx = data_col_indices[idx];
                SortTrackedColOracle {
                    expr: output_sort_table.tracked_col_oracle_by_ind(col_idx),
                    asc: sort_expr.asc,
                    nulls_first: sort_expr.nulls_first,
                }
            })
            .collect();

        let verifier_input = SortPIOPVerifierInput {
            sort: sort_plan,
            input_sort_exprs,
            output_sort_exprs,
            input_table,
            output_table,
        };

        SortPIOP::<F, MvPCS, UvPCS>::verify(verifier, verifier_input)?;

        self.children()
            .iter()
            .try_for_each(|child| child.verify_piop(verifier, piop_tree))?;

        Ok(())
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        self.input_verifier_node.clone()
    }
}
