use datafusion::{
    logical_expr::{
        LogicalPlan, LogicalPlan::Projection, LogicalPlanBuilder, expr_rewriter::normalize_cols,
    },
    prelude::{SessionContext, col},
};

use std::{collections::HashMap, sync::Arc};

use crate::trees::proof_tree::{
    ProofTree,
    nodes::{ProverNode, ProverNodeNodeId, expr_to_proof_plan, output_logical_plan},
};
/// Projection operator that preserves the `activator` column.
///
/// - `expr`: projection expressions from the original logical plan
/// - `input`: child proof node
/// - witness plans include a single logical plan entry named `"output"`
///   representing the projection with the `activator` column retained.
pub struct ProjectionNode {
    pub expr_proof_plans: Vec<Arc<dyn ProverNode>>,
    pub input_proof_plan: Arc<dyn ProverNode>,
    pub node_id: ProverNodeNodeId,
    pub hint_generation_plans: HashMap<String, LogicalPlan>,
}

impl ProverNode for ProjectionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        let mut children = Vec::with_capacity(1 + self.expr_proof_plans.len());
        children.push(&self.input_proof_plan);
        for expr_plan in &self.expr_proof_plans {
            children.push(expr_plan);
        }
        children
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        let projection = match &plan {
            Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // projection.
        let input_tree = ProofTree::from_logical_plan(ctx, &projection.input);
        let input_proof_plan = input_tree.root();
        let child_output_plan =
            output_logical_plan(&input_proof_plan).unwrap_or_else(|| (*projection.input).clone());

        // Normalize the projection expressions against the child plan.
        let mut normalized_exprs = normalize_cols(projection.expr.clone(), &child_output_plan)
            .expect("failed to normalize projection expressions");
        let original_exprs = normalized_exprs.clone();

        // Ensure the activator column is preserved in the output.
        let activator_present = projection
            .schema
            .field_with_unqualified_name("activator")
            .is_ok();
        if !activator_present {
            let mut activator_expr = normalize_cols(vec![col("activator")], &child_output_plan)
                .expect("failed to normalize activator column");
            normalized_exprs.push(activator_expr.pop().expect("missing activator expression"));
        }

        let output_plan = LogicalPlanBuilder::from(child_output_plan.clone())
            .project(normalized_exprs.clone())
            .expect("failed to apply projection")
            .build()
            .expect("failed to build projection logical plan");

        // Build expression proof plans for the projection expressions (excluding the
        // retained activator).
        let expr_proof_plans = original_exprs
            .into_iter()
            .map(|expr| expr_to_proof_plan(ctx, expr, &output_plan))
            .collect();

        let hint_generation_plans = HashMap::from([("output".to_string(), output_plan.clone())]);

        Self {
            expr_proof_plans,
            input_proof_plan,
            node_id: ProverNodeNodeId::LP(plan),
            hint_generation_plans,
        }
    }

    fn piop_plan(&self) {
        todo!()
    }
}
