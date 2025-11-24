use datafusion::{
    arrow::datatypes::FieldRef,
    logical_expr::{Expr, LogicalPlanBuilder},
    prelude::DataFrame,
};
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;

pub mod cost;
pub mod exprs;
pub mod gadgets;
pub mod lps;
pub mod prover;
pub mod verifier;

#[derive(Clone)]
pub struct HintDF {
    data_fram: DataFrame,
    should_materialize: IndexMap<FieldRef, bool>,
}

impl HintDF {
    pub fn new(data_fram: DataFrame, should_materialize: IndexMap<FieldRef, bool>) -> Self {
        Self {
            data_fram,
            should_materialize,
        }
    }

    pub fn new_materialized(plan: DataFrame) -> Self {
        Self::new_with_mat_flag(plan, true)
    }

    pub fn new_virtual(plan: DataFrame) -> Self {
        Self::new_with_mat_flag(plan, false)
    }

    fn new_with_mat_flag(data_fram: DataFrame, materialized: bool) -> Self {
        let should_materialize = data_fram
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), materialized))
            .collect();
        Self {
            data_fram,
            should_materialize,
        }
    }

    pub fn data_frame(&self) -> &DataFrame {
        &self.data_fram
    }

    pub fn should_materialize(&self, field: &FieldRef) -> Option<&bool> {
        self.should_materialize.get(field)
    }

    pub fn field_materialization_iter(&self) -> impl Iterator<Item = (&FieldRef, &bool)> {
        self.should_materialize.iter()
    }

    pub fn project_materialized(&self) -> Option<LogicalPlan> {
        todo!()
        // let schema = self.plan.schema();
        // let projection_exprs: Vec<Expr> = schema
        //     .iter()
        //     .filter(|&(_qualifier, field)| {
        //         self.should_materialize.get(field).copied().unwrap_or(false)
        //     })
        //     .map(|(qualifier, field)| Expr::from((qualifier, field)))
        //     .collect();

        // if projection_exprs.len() == schema.fields().len() {
        //     return Some(self.plan.clone());
        // }

        // if projection_exprs.is_empty() {
        //     return None;
        // }

        // LogicalPlanBuilder::from(self.plan.clone())
        //     .project(projection_exprs)
        //     .expect("failed to build projection for materialized columns")
        //     .build()
        //     .ok()
    }
}
