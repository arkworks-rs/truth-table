use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode,
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
        self as df, LogicalPlan, LogicalPlan::Projection, LogicalPlanBuilder,
        expr_rewriter::normalize_cols,
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
    pub expr_prover_nodes: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub input_prover_node: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, (LogicalPlan, bool)>,
}
pub struct VerifierProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr_verifier_nodes: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub input_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, (LogicalPlan, bool)>,
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

    LogicalPlanBuilder::from(base_plan)
        .project(normalized_exprs)
        .expect("failed to attach projection expressions for hint plan")
        .build()
        .expect("failed to finalize projection hint plan")
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverProjectionNode<F, MvPCS, UvPCS>
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
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        let projection_plan = match self.node_id.to_lp() {
            Some(Projection(p)) => p.clone(),
            _ => panic!("expected projection logical plan"),
        };

        let base_plan = proof_tree
            .node(&self.input_prover_node.node_id())
            .and_then(|node| {
                node.hint_generation_plans(proof_tree)
                    .get(OUTPUT_PLAN_KEY)
                    .map(|(plan, _)| plan.clone())
            })
            .expect("projection input missing OUTPUT_PLAN hint");

        let output_plan = build_projection_hint_plan(base_plan, &projection_plan);

        IndexMap::from([(OUTPUT_PLAN_KEY.to_string(), (output_plan, true))])
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
        // Get the projection object from the logical plan
        let projection = match &plan {
            Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };
        // Build the node id for this projection node
        let node_id = NodeId::LP(plan.clone());

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
            input_prover_node,
            node_id,
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

    fn ctx_lp_node(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        self.input_prover_node.clone()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        if self.expr_prover_nodes.is_empty() {
            return;
        }

        let expr_tables: Option<Vec<_>> = self
            .expr_prover_nodes
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
                    .tracked_table(&self.input_prover_node.node_id(), OUTPUT_PLAN_KEY)
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
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        self.children()
            .iter()
            .try_for_each(|child| child.prove_piop(prover, piop_tree))?;
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
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        let projection_plan = match self.node_id.to_lp() {
            Some(Projection(p)) => p.clone(),
            _ => panic!("expected projection logical plan"),
        };

        let base_plan = proof_tree
            .node(&self.input_verifier_node.node_id())
            .and_then(|node| {
                node.hint_generation_plans(proof_tree)
                    .get(OUTPUT_PLAN_KEY)
                    .map(|(plan, _)| plan.clone())
            })
            .expect("projection input missing OUTPUT_PLAN hint");

        let output_plan = build_projection_hint_plan(base_plan, &projection_plan);

        IndexMap::from([(OUTPUT_PLAN_KEY.to_string(), (output_plan, true))])
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
        // Get the projection object from the logical plan
        let projection = match &plan {
            Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };
        // Build the node id for this projection node

        let node_id = NodeId::LP(plan.clone());

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
            input_verifier_node,
            node_id,
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
        if self.expr_verifier_nodes.is_empty() {
            return;
        }

        let expr_tables: Option<Vec<_>> = self
            .expr_verifier_nodes
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
                    .tracked_table_oracle(&self.input_verifier_node.node_id(), OUTPUT_PLAN_KEY)
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
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
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
