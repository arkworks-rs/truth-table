use datafusion::{
    logical_expr::{LogicalPlan, LogicalPlan::Projection, LogicalPlanBuilder},
    prelude::{Expr, SessionContext, col},
};
use std::{collections::HashMap, sync::Arc};

use crate::{
    nodes::{ProverNode, ProverNodeNodeId, expr_to_proof_plan, output_logical_plan},
    trees::proof_tree::ProofTree,
};
/// Projection operator that preserves the `activator` column.
///
/// - `expr`: projection expressions from the original logical plan
/// - `input`: child proof node
/// - witness plans include the relative projection ("output_plan") and the
///   relative projection plan ("relative_output").
pub struct ProjectionNode {
    pub expr_proof_plans: Vec<Arc<dyn ProverNode>>,
    pub input_proof_plan: Arc<dyn ProverNode>,
    pub node_id: ProverNodeNodeId,
    pub proof_trees: HashMap<String, LogicalPlan>,
}

impl ProjectionNode {
    /// Check if the projection expression already includes the `activator`
    /// column
    fn already_projects_activator(expr: &Expr) -> bool {
        match expr {
            Expr::Column(c) => c.name == "activator",
            Expr::Alias(a) => a.name == "activator",
            Expr::Wildcard { .. } => true,
            _ => false,
        }
    }

    /// The projection expressions need to include `activator` column
    fn project_activator(mut exprs: Vec<Expr>, input_plan: &LogicalPlan) -> Vec<Expr> {
        let schema = input_plan.schema();
        if schema.field_with_unqualified_name("activator").is_ok() {
            let has_activator = exprs.iter().any(Self::already_projects_activator);
            if !has_activator {
                exprs.push(col("activator"));
            }
        }
        exprs
    }

    pub fn build_output_logical_plan(exprs: Vec<Expr>, input_plan: LogicalPlan) -> LogicalPlan {
        LogicalPlanBuilder::from(input_plan)
            .project(exprs)
            .unwrap()
            .build()
            .unwrap()
    }
}
impl ProverNode for ProjectionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        let mut children: Vec<&Arc<dyn ProverNode>> =
            Vec::with_capacity(self.expr_proof_plans.len() + 1);
        children.push(&self.input_proof_plan);
        children.extend(self.expr_proof_plans.iter());
        children
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn proof_trees(&self) -> HashMap<String, LogicalPlan> {
        self.proof_trees.clone()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        // Match only on projection logical plan
        let projection = match &plan {
            Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };
        // The input is itself a logical plan and needs to be proved
        let input_proof_plan = ProofTree::from_logical_plan(ctx, &projection.input);
        // Fetching the output logical plan of the input logical plan
        let child_plan = output_logical_plan(&input_proof_plan.root()).unwrap();
        let normalized_exprs = Self::project_activator(projection.expr.clone(), &child_plan);
        // Build the output logical plan for this projection node on top of the child
        // output logical plan
        let output_plan =
            Self::build_output_logical_plan(normalized_exprs.clone(), child_plan.clone());
        // The exprs need to be proved
        let expr_proof_plans: Vec<Arc<dyn ProverNode>> = normalized_exprs
            .into_iter()
            .map(|e| expr_to_proof_plan(ctx, e, &child_plan))
            .collect();
        let mut proof_trees = HashMap::new();
        proof_trees.insert("output_plan".to_string(), output_plan.clone());
        ProjectionNode {
            expr_proof_plans,
            input_proof_plan: input_proof_plan.root(),
            node_id: ProverNodeNodeId::LP(plan),
            proof_trees,
        }
    }

    fn piop_plan(&self) {
        todo!()
    }
}
