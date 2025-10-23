use datafusion::arrow::datatypes::FieldRef;
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;

pub mod cost;
pub mod display;
pub mod exprs;
pub mod id;
pub mod lps;
pub mod prover;
pub mod verifier;

pub const OUTPUT_PLAN_KEY: &str = "output_plan";

pub struct HintGenerationPlan {
    name: String,
    plan: LogicalPlan,
    should_materialize: IndexMap<FieldRef, bool>,
}

impl HintGenerationPlan {
    pub fn new(
        name: String,
        plan: LogicalPlan,
        should_materialize: IndexMap<FieldRef, bool>,
    ) -> Self {
        Self {
            name,
            plan,
            should_materialize,
        }
    }

    pub fn new_materialized(name: String, plan: LogicalPlan) -> Self {
        Self::new_with_mat_flag(name, plan, true)
    }

    pub fn new_virtual(name: String, plan: LogicalPlan) -> Self {
        Self::new_with_mat_flag(name, plan, true)
    }

    fn new_with_mat_flag(name: String, plan: LogicalPlan, materialized: bool) -> Self {
        let should_materialize = plan
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), materialized))
            .collect();
        Self {
            name,
            plan,
            should_materialize,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn plan(&self) -> &LogicalPlan {
        &self.plan
    }

    pub fn should_materialize(&self, field: &FieldRef) -> Option<&bool> {
        self.should_materialize.get(field)
    }
}
