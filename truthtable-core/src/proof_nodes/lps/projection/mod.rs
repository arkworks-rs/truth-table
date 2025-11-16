use crate::proof_nodes::HintGenerationPlan;

use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId,
        prover::{ProverGadgetNode, ProverLpNode, ProverNode},
        verifier::{VerifierNode, VerifierLpNode},
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    arrow::datatypes::{Field, FieldRef, Schema},
    logical_expr::{
        self as df, LogicalPlan,
        LogicalPlan::Projection,
        LogicalPlanBuilder,
        expr_rewriter::{normalize_cols, unnormalize_cols},
    },
    prelude::{SessionContext, col},
};
use datafusion::prelude::DataFrame;

use indexmap::IndexMap;
use std::{collections::HashSet, sync::Arc};

#[cfg(test)]
mod tests;

pub struct ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr_prover_nodes: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub activator_expr_indexes: Vec<usize>,
    pub input_prover_node: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, HintGenerationPlan>,
}
pub struct VerifierProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr_verifier_nodes: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub activator_expr_indexes: Vec<usize>,
    pub input_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, HintGenerationPlan>,
}

fn build_projection_hint_plan(base_plan: LogicalPlan, projection: &df::Projection) -> LogicalPlan {
    let base_schema = base_plan.schema();
    let mut projection_exprs = projection.expr.clone();

    let base_has_activator = base_schema
        .field_with_unqualified_name(ACTIVATOR_COL_NAME)
        .is_ok();
    let projection_includes_activator = projection
        .schema
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);

    if base_has_activator && !projection_includes_activator {
        projection_exprs.push(col(ACTIVATOR_COL_NAME));
    }

    let normalized_exprs = normalize_cols(projection_exprs, &base_plan)
        .expect("failed to normalize projection expressions for hint plan");
    let normalized_exprs = unnormalize_cols(normalized_exprs);

    LogicalPlanBuilder::from(base_plan)
        .project(normalized_exprs)
        .expect("failed to attach projection expressions for hint plan")
        .build()
        .expect("failed to finalize projection hint plan")
}

impl<F, MvPCS, UvPCS> ProverGadgetNode<F, MvPCS, UvPCS>
    for ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::with_capacity(1 + self.expr_prover_nodes.len());
        children.push(&self.input_prover_node);
        for expr_plan in &self.expr_prover_nodes {
            children.push(expr_plan);
        }
        children
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
        todo!()
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
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn arithmetic_post_process(
        &self,
        _arithmetized_tree: &mut crate::prover::trees::arithmetized_tree::ProverArithmetizedTree<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn output_data_frame(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the projection object from the logical plan
        let projection = match &plan {
            Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };
        // Build the node id for this projection node
        let node_id = NodeId::LP(plan.clone());

        let activator_expr_indexes: Vec<usize> = projection
            .schema
            .fields()
            .iter()
            .enumerate()
            .filter_map(|(idx, field)| {
                if field.name() == ACTIVATOR_COL_NAME {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // projection.
        let input_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &projection.input,
            &node_id,
        )
        .root();
        // Build expression proof plans for the projection expressions (excluding the
        // retained activator).
        let expr_prover_nodes = projection
            .expr
            .clone()
            .into_iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr,
                    &node_id,
                )
                .root()
            })
            .collect();

        // Projection does not have any materialized witness
        let hint_generation_plans = IndexMap::new();

        Self {
            expr_prover_nodes,
            activator_expr_indexes,
            input_prover_node,
            node_id,
            hint_generation_plans,
        }
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::with_capacity(1 + self.expr_verifier_nodes.len());
        children.push(&self.input_verifier_node);
        for expr_plan in &self.expr_verifier_nodes {
            children.push(expr_plan);
        }
        children
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
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

    fn add_virtual_witness(
        &self,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }


    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        todo!()
    }



    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }


    fn output_data_frame(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }


    fn is_public(&self) -> bool {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> VerifierLpNode<F, MvPCS, UvPCS> for VerifierProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the projection object from the logical plan
        let projection = match &plan {
            Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };
        // Build the node id for this projection node

        let node_id = NodeId::LP(plan.clone());

        let activator_expr_indexes: Vec<usize> = projection
            .schema
            .fields()
            .iter()
            .enumerate()
            .filter_map(|(idx, field)| {
                if field.name() == ACTIVATOR_COL_NAME {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // projection.
        let input_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &projection.input,
            &node_id,
        )
        .root();
        // Build expression proof plans for the projection expressions (excluding the //
        // retained activator).
        let expr_verifier_nodes = projection
            .clone()
            .expr
            .into_iter()
            .map(|expr| {
                VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr,
                    &node_id,
                )
                .root()
            })
            .collect();

        let hint_generation_plans = IndexMap::new();

        Self {
            expr_verifier_nodes,
            activator_expr_indexes,
            input_verifier_node,
            node_id,
            hint_generation_plans,
        }
    }
}
