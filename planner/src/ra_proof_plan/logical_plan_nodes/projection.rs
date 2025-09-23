use crate::ra_proof_plan::{
    expr_to_proof_plan, logical_to_proof_plan, output_logical_plan, ProofPlan, ProofPlanNodeType,
};
use datafusion::{
    logical_expr::{LogicalPlan, LogicalPlan::Projection, LogicalPlanBuilder},
    prelude::{col, Expr, SessionContext},
};
use std::{collections::HashMap, sync::Arc};
/// Projection operator that preserves the `activator` column.
///
/// - `expr`: projection expressions from the original logical plan
/// - `input`: child proof node
/// - witness plans include the relative projection ("output_plan") and the
///   relative projection plan ("relative_output").
pub struct ProjectionNode {
    pub expr_proof_plans: Vec<Arc<dyn ProofPlan>>,
    pub input_proof_plan: Arc<dyn ProofPlan>,
    pub node_type: ProofPlanNodeType,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
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
impl ProofPlan for ProjectionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        let mut children: Vec<&Arc<dyn ProofPlan>> =
            Vec::with_capacity(self.expr_proof_plans.len() + 1);
        children.push(&self.input_proof_plan);
        children.extend(self.expr_proof_plans.iter());
        children
    }

    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.witness_generation_plans.clone()
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
        let input_proof_plan = logical_to_proof_plan(ctx, &projection.input);
        // Fetching the output logical plan of the input logical plan
        let child_plan = output_logical_plan(&input_proof_plan).unwrap();
        let normalized_exprs = Self::project_activator(projection.expr.clone(), &child_plan);
        // Build the output logical plan for this projection node on top of the child
        // output logical plan
        let output_plan =
            Self::build_output_logical_plan(normalized_exprs.clone(), child_plan.clone());
        // The exprs need to be proved
        let expr_proof_plans: Vec<Arc<dyn ProofPlan>> = normalized_exprs
            .into_iter()
            .map(|e| expr_to_proof_plan(ctx, e, &child_plan))
            .collect();
        let mut witness_generation_plans = HashMap::new();
        witness_generation_plans.insert("output_plan".to_string(), output_plan.clone());
        ProjectionNode {
            expr_proof_plans,
            input_proof_plan,
            node_type: ProofPlanNodeType::LogicalPlan(plan),
            witness_generation_plans,
        }
    }
}
