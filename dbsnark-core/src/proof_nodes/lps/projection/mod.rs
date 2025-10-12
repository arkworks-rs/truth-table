

use crate::{
    proof_nodes::{
        cost::ProvingCost,
        id::NodeId,
        prover::{output_prover_logical_plan, ProverNode},
        verifier::{output_verifier_logical_plan, VerifierNode}, OUTPUT_PLAN_KEY,
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{
    logical_expr::{
        LogicalPlan, LogicalPlan::Projection, LogicalPlanBuilder, expr_rewriter::normalize_cols,
    },
    prelude::{SessionContext, col},
};
use indexmap::IndexMap;
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub struct ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr_proof_plans: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub input_proof_plan: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, LogicalPlan>,
}
pub struct VerifierProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr_proof_plans: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub input_proof_plan: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, LogicalPlan>,
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::with_capacity(1 + self.expr_proof_plans.len());
        children.push(&self.input_proof_plan);
        for expr_plan in &self.expr_proof_plans {
            children.push(expr_plan);
        }
        children
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> IndexMap<String, LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        let projection = match &plan {
            Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // projection.
        let input_tree =
            ProverProofTree::<F, MvPCS, UvPCS>::from_lp(ctx, prover_ctx.clone(), &projection.input);
        let input_proof_plan = input_tree.root();
        let child_output_plan = output_prover_logical_plan::<F, MvPCS, UvPCS>(&input_proof_plan)
            .unwrap_or_else(|| (*projection.input).clone());

        // Normalize the projection expressions against the child plan.
        let normalized_exprs = normalize_cols(projection.expr.clone(), &child_output_plan)
            .expect("failed to normalize projection expressions");
        let original_exprs = normalized_exprs.clone();

        // Build expression proof plans for the projection expressions (excluding the
        // retained activator).
        let expr_proof_plans = original_exprs
            .into_iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(ctx, prover_ctx.clone(), expr, &plan)
            })
            .collect();

        // Projection does not have any materialized witness
        let hint_generation_plans = IndexMap::new();

        Self {
            expr_proof_plans,
            input_proof_plan,
            node_id: NodeId::LP(plan),
            hint_generation_plans,
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        if self.expr_proof_plans.is_empty() {
            return;
        }

        let expr_tables: Option<Vec<_>> = self
            .expr_proof_plans
            .iter()
            .map(|plan| piop_tree.tracked_table(&plan.node_id(), OUTPUT_PLAN_KEY))
            .collect();

        let expr_tables = match expr_tables {
            Some(tables) => tables,
            None => return,
        };

        let table_size = expr_tables[0].size();
        let table_log_size = expr_tables[0].log_size();
        if expr_tables.iter().any(|table| table.size() != table_size) {
            panic!("projection expression tables must have matching sizes");
        }

        let mut data_columns = IndexMap::with_capacity(expr_tables.len() + 1);
        for table in &expr_tables {
            let tracked_polys = table.tracked_polys();
            let (field, poly) = tracked_polys
                .iter()
                .find(|(field, _)| field.name() != ACTIVATOR_COL_NAME)
                .expect("expression output must contain data column");
            data_columns.insert(field.clone(), poly.clone());
        }

        let activator_pair = expr_tables[0]
            .tracked_polys()
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
            .or_else(|| {
                piop_tree
                    .tracked_table(&self.input_proof_plan.node_id(), OUTPUT_PLAN_KEY)
                    .and_then(|table| {
                        table
                            .tracked_polys()
                            .iter()
                            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
                            .map(|(field, poly)| (field.clone(), poly.clone()))
                    })
            })
            .expect("activator column not found for projection");

        data_columns.insert(activator_pair.0, activator_pair.1);

        let output_table = TrackedTable::new(None, data_columns, table_log_size);
        piop_tree.add_table(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_string(),
            output_table,
        );
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::with_capacity(1 + self.expr_proof_plans.len());
        children.push(&self.input_proof_plan);
        for expr_plan in &self.expr_proof_plans {
            children.push(expr_plan);
        }
        children
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> IndexMap<String, LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        let projection = match &plan {
            Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };

        // // Recurse into the input subtree and fetch the logical plan that
        // feeds this // projection.
        let input_tree = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &projection.input,
        );
        let input_proof_plan = input_tree.root();
        let child_output_plan = output_verifier_logical_plan::<F, MvPCS, UvPCS>(&input_proof_plan)
            .unwrap_or_else(|| (*projection.input).clone());

        // // Normalize the projection expressions against the child plan.
        let mut normalized_exprs = normalize_cols(projection.expr.clone(), &child_output_plan)
            .expect(
                "failed to normalize
        projection expressions",
            );
        let original_exprs = normalized_exprs.clone();

        // // Ensure the activator column is preserved in the output.
        let activator_present = projection
            .schema
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .is_ok();
        if !activator_present {
            let mut activator_expr =
                normalize_cols(vec![col(ACTIVATOR_COL_NAME)], &child_output_plan).expect(
                    "failed to normalize
        activator column",
                );
            normalized_exprs.push(activator_expr.pop().expect("missing activator expression"));
        }

        let output_plan = LogicalPlanBuilder::from(child_output_plan.clone())
            .project(normalized_exprs.clone())
            .expect("failed to apply projection")
            .build()
            .expect("failed to build projection logical plan");

        // Build expression proof plans for the projection expressions (excluding the //
        // retained activator).
        let expr_proof_plans = original_exprs
            .into_iter()
            .map(|expr| {
                VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr,
                    &output_plan,
                )
            })
            .collect();

        let hint_generation_plans = IndexMap::new();

        Self {
            expr_proof_plans,
            input_proof_plan,
            node_id: NodeId::LP(plan),
            hint_generation_plans,
        }
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

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        if self.expr_proof_plans.is_empty() {
            return;
        }

        let expr_tables: Option<Vec<_>> = self
            .expr_proof_plans
            .iter()
            .map(|plan| piop_tree.tracked_table_oracle(&plan.node_id(), OUTPUT_PLAN_KEY))
            .collect();

        let expr_tables = match expr_tables {
            Some(tables) => tables,
            None => return,
        };

        let table_log_size = expr_tables[0].log_size();
        if expr_tables
            .iter()
            .any(|table| table.log_size() != table_log_size)
        {
            panic!("projection expression tables must have matching sizes");
        }

        let mut data_columns = Vec::with_capacity(expr_tables.len() + 1);
        for table in &expr_tables {
            let tracked_oracles = table.tracked_oracles();
            let (field, poly) = tracked_oracles
                .iter()
                .find(|(field, _)| field.name() != ACTIVATOR_COL_NAME)
                .expect("expression output must contain data column");
            data_columns.push((field.clone(), poly.clone()));
        }

        let activator_pair = expr_tables[0]
            .tracked_oracles()
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
            .or_else(|| {
                piop_tree
                    .tracked_table_oracle(&self.input_proof_plan.node_id(), OUTPUT_PLAN_KEY)
                    .and_then(|table| {
                        table
                            .tracked_oracles()
                            .iter()
                            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
                            .map(|(field, poly)| (field.clone(), poly.clone()))
                    })
            })
            .expect("activator column not found for projection");
        data_columns.push(activator_pair);

        let tracked_oracles: IndexMap<_, _> = data_columns.into_iter().collect();
        let output_table = TrackedTableOracle::new(None, tracked_oracles, table_log_size);
        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_string(),
            output_table,
        );
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}
