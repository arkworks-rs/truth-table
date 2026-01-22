use arithmetic::ROW_ID_COL_NAME;
use ark_std::fmt::Display;
use datafusion::{arrow::datatypes::FieldRef, prelude::DataFrame};
use datafusion_common::{Column, Result as DataFusionResult};
use datafusion_expr::{Expr, LogicalPlan, SortExpr, col};
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
        let (data_fram, should_materialize) = normalize_hint_df(data_fram, should_materialize);
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
        let (data_fram, should_materialize) = normalize_hint_df(data_fram, should_materialize);
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
    let row_id_sort_exprs: Vec<SortExpr> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != ROW_ID_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).sort(true, true))
        })
        .collect();
    if row_id_sort_exprs.is_empty() {
        return Ok(df);
    }
    df.sort(row_id_sort_exprs)
}

pub fn append_row_id_expr_if_present(df: &DataFrame, exprs: &mut Vec<Expr>) {
    let row_id_exprs: Vec<Expr> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != ROW_ID_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(
                qualifier.cloned(),
                ROW_ID_COL_NAME,
            )))
        })
        .collect();
    if row_id_exprs.is_empty() {
        return;
    }
    let mut qualified: Vec<Expr> = row_id_exprs
        .iter()
        .cloned()
        .filter(|expr| matches!(expr, Expr::Column(col) if col.relation.is_some()))
        .collect();
    let row_expr = if !qualified.is_empty() {
        qualified.remove(0)
    } else if row_id_exprs.len() == 1 {
        row_id_exprs[0].clone()
    } else {
        return;
    };

    let row_col = match &row_expr {
        Expr::Column(col) => col,
        _ => return,
    };
    let already_present = exprs.iter().any(|expr| match expr {
        Expr::Column(col) => col.name == row_col.name && col.relation == row_col.relation,
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
        exprs.insert(pos, row_expr);
        return;
    }
    exprs.push(row_expr);
}

pub fn append_activator_exprs_if_present(df: &DataFrame, exprs: &mut Vec<Expr>) {
    let activator_exprs: Vec<Expr> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != arithmetic::ACTIVATOR_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(
                qualifier.cloned(),
                arithmetic::ACTIVATOR_COL_NAME,
            )))
        })
        .collect();
    if activator_exprs.is_empty() {
        return;
    }
    let mut to_insert = Vec::new();
    for activator_expr in activator_exprs {
        let activator_col = match &activator_expr {
            Expr::Column(col) => col,
            _ => continue,
        };
        let already_present = exprs.iter().any(|expr| match expr {
            Expr::Column(col) => {
                col.name == activator_col.name && col.relation == activator_col.relation
            }
            _ => false,
        });
        if !already_present {
            to_insert.push(activator_expr);
        }
    }
    if to_insert.is_empty() {
        return;
    }
    exprs.extend(to_insert);
}

pub fn strip_row_id_from_hint(hint: &HintDF) -> HintDF {
    let df = hint.data_frame().clone();
    let has_row_id = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    if !has_row_id {
        return hint.clone();
    }

    // Row-id is only for deterministic ordering, so drop it before storing payloads.
    let projected: Vec<Expr> = df
        .schema()
        .fields()
        .iter()
        .filter_map(|field| (field.name() != ROW_ID_COL_NAME).then_some(col(field.name())))
        .collect();
    let projected_df = df
        .select(projected)
        .expect("row-id projection should succeed");

    let mut should_materialize = IndexMap::new();
    for field in projected_df.schema().fields() {
        let materialized = hint
            .field_materialization_iter()
            .find(|(orig_field, _)| orig_field.name() == field.name())
            .map(|(_, materialized)| *materialized)
            .unwrap_or(true);
        should_materialize.insert(field.clone(), materialized);
    }

    HintDF::new(projected_df, should_materialize)
}

fn normalize_hint_df(
    data_fram: DataFrame,
    should_materialize: IndexMap<FieldRef, bool>,
) -> (DataFrame, IndexMap<FieldRef, bool>) {
    let schema = data_fram.schema();
    let original_fields: Vec<FieldRef> = schema.fields().iter().cloned().collect();
    let projection: Vec<Expr> = schema
        .iter()
        .map(|(qualifier, field)| {
            if let Some(qualifier) = qualifier {
                Expr::Column(Column::new(Some(qualifier.clone()), field.name()))
            } else {
                Expr::Column(Column::new_unqualified(field.name()))
            }
        })
        .collect();

    let already_normalized = match data_fram.logical_plan() {
        LogicalPlan::Projection(proj) => {
            proj.expr.len() == projection.len()
                && proj
                    .expr
                    .iter()
                    .zip(projection.iter())
                    .all(|(expr, expected)| {
                        matches!(
                            (expr, expected),
                            (Expr::Column(actual), Expr::Column(expected)) if actual == expected
                        )
                    })
        }
        _ => false,
    };

    let normalized_df = if already_normalized {
        data_fram
    } else {
        data_fram
            .select(projection)
            .expect("hint dataframe normalization should succeed")
    };

    let mut normalized_should_materialize = IndexMap::new();
    for (idx, field) in normalized_df.schema().fields().iter().enumerate() {
        let original_field = &original_fields[idx];
        let should = should_materialize
            .get(original_field)
            .copied()
            .unwrap_or(true);
        normalized_should_materialize.insert(field.clone(), should);
    }

    (normalized_df, normalized_should_materialize)
}
