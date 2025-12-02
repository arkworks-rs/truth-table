use ark_std::fmt::Display;
use datafusion::{arrow::datatypes::FieldRef, prelude::DataFrame};
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;

#[derive(Clone, Debug)]
pub struct HintDF {
    data_fram: DataFrame,
    should_materialize: IndexMap<FieldRef, bool>,
}
impl Display for HintDF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (materialized, virtualized): (Vec<_>, Vec<_>) =
            self.should_materialize.iter().partition(|(_, mat)| **mat);

        let materialized_cols: Vec<String> = materialized
            .into_iter()
            .map(|(field, _)| field.name().to_string())
            .collect();
        let virtual_cols: Vec<String> = virtualized
            .into_iter()
            .map(|(field, _)| field.name().to_string())
            .collect();

        writeln!(f, "HintDF with {} columns", self.should_materialize.len())?;
        writeln!(f, "Materialized: ({})", materialized_cols.join(","))?;
        write!(f, "Virtual: ({})", virtual_cols.join(","))
    }
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
