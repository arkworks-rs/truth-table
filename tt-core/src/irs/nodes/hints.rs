use arithmetic::ROW_ID_COL_NAME;
use ark_std::fmt::Display;
use datafusion::{arrow::datatypes::FieldRef, prelude::DataFrame};
use datafusion_common::Result as DataFusionResult;
use datafusion_expr::{Expr, LogicalPlan, col};
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

pub fn sort_by_row_id_if_present(df: DataFrame) -> DataFusionResult<DataFrame> {
    let has_row_id = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    if has_row_id {
        df.sort(vec![col(ROW_ID_COL_NAME).sort(true, true)])
    } else {
        Ok(df)
    }
}

pub fn append_row_id_expr_if_present(df: &DataFrame, exprs: &mut Vec<Expr>) {
    let has_row_id = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    if !has_row_id {
        return;
    }
    let already_present = exprs.iter().any(|expr| match expr {
        Expr::Column(col) => col.name == ROW_ID_COL_NAME,
        _ => false,
    });
    if already_present {
        return;
    }
    let insert_pos = exprs.iter().position(|expr| match expr {
        Expr::Column(col) => col.name == arithmetic::ACTIVATOR_COL_NAME,
        _ => false,
    });
    if let Some(pos) = insert_pos {
        exprs.insert(pos, arithmetic::ROW_ID_EXPR.clone());
    } else {
        exprs.push(arithmetic::ROW_ID_EXPR.clone());
    }
}
