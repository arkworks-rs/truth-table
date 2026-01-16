use crate::irs::nodes::gadget::utils::contig_sort::{
    DIFF_INPUT_LABEL, ROTATED_INPUT_LABEL, TIE_INDICATOR_LABEL,
};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use datafusion::logical_expr::Expr;
use datafusion::logical_expr::col;
use datafusion::logical_expr::lit;
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::ExprFunctionExt;
use datafusion_expr::SortExpr;
use datafusion_expr::when;
use datafusion_expr::{Cast, Operator, expr::BinaryExpr};

use datafusion::functions_window::expr_fn::{first_value, lead};
use indexmap::IndexMap;
pub(crate) fn populate_rotated(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) {
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    let rotated_df =
        rotate(input_hint.data_frame().clone(), order_by).expect("sort rotate planning should succeed");
    let should_materialize = rotated_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    let rotated_hint = crate::irs::nodes::hints::HintDF::new(rotated_df, should_materialize);
    gadget_payload.insert(ROTATED_INPUT_LABEL.to_string(), rotated_hint);
}

pub(crate) fn populate_tie_indicator(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) {
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    let tie_df = tie_indicator(input_hint.data_frame().clone(), order_by, sort_specs)
        .expect("sort tie indicator planning should succeed");
    let should_materialize = tie_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    let tie_hint = crate::irs::nodes::hints::HintDF::new(tie_df, should_materialize);
    gadget_payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_hint);
}

pub(crate) fn populate_diff(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) {
    // Materialize per-column diffs so sign checks see in-range values.
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    let diff_df = diff_input(input_hint.data_frame().clone(), order_by, sort_specs)
        .expect("sort diff planning should succeed");
    let should_materialize = diff_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    let diff_hint = crate::irs::nodes::hints::HintDF::new(diff_df, should_materialize);
    gadget_payload.insert(DIFF_INPUT_LABEL.to_string(), diff_hint);
}

pub(crate) fn sort_input_for_contig_sort(
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    input_hint.data_frame().clone().sort(order_by)
}

pub(crate) fn rotate(df: DataFrame, order_by: Vec<SortExpr>) -> DataFusionResult<DataFrame> {
    let has_row_id = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let order_by = if !order_by.is_empty() {
        order_by
    } else if has_row_id {
        vec![col(ROW_ID_COL_NAME).sort(true, true)]
    } else {
        return Err(DataFusionError::Plan(format!(
            "rotate requires {} column for deterministic ordering",
            ROW_ID_COL_NAME
        )));
    };

    let ordered = df.sort(order_by.clone())?;
    let mut rotated_cols = Vec::new();

    for field in ordered.schema().fields() {
        let name = field.name();
        if name == ROW_ID_COL_NAME {
            continue;
        }
        let lead_expr = lead(col(name), Some(1), None)
            .order_by(order_by.clone())
            .build()?;
        let first_expr = first_value(col(name)).order_by(order_by.clone()).build()?;
        let rotated_expr = when(lead_expr.clone().is_null(), first_expr)
            .otherwise(lead_expr)?
            .alias(name.to_string());
        rotated_cols.push(rotated_expr);
    }

    ordered.select(rotated_cols)
}

pub(crate) fn diff_input(
    df: DataFrame,
    order_by: Vec<SortExpr>,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let schema = df.schema();
    let has_row_id = schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let order_by = if !order_by.is_empty() {
        order_by
    } else if has_row_id {
        vec![col(ROW_ID_COL_NAME).sort(true, true)]
    } else {
        return Err(DataFusionError::Plan(format!(
            "diff_input requires {} column for deterministic ordering",
            ROW_ID_COL_NAME
        )));
    };

    let ordered = df.sort(order_by.clone())?;
    let mut diff_cols = Vec::new();

    for field in ordered.schema().fields() {
        let name = field.name();
        if is_system_column(name) {
            continue;
        }
        let lead_expr = lead(col(name), Some(1), None)
            .order_by(order_by.clone())
            .build()?;
        let first_expr = first_value(col(name)).order_by(order_by.clone()).build()?;
        let rotated_expr = when(lead_expr.clone().is_null(), first_expr)
            .otherwise(lead_expr)?;
        let is_asc = sort_is_asc(sort_specs, name);
        // Date32 subtraction yields a duration, so cast to Int32 before subtracting.
        let diff_expr = if field.data_type() == &datafusion::arrow::datatypes::DataType::Date32 {
            let lhs = Expr::Cast(Cast {
                expr: Box::new(if is_asc {
                    rotated_expr.clone()
                } else {
                    col(name)
                }),
                data_type: datafusion::arrow::datatypes::DataType::Int32,
            });
            let rhs = Expr::Cast(Cast {
                expr: Box::new(if is_asc {
                    col(name)
                } else {
                    rotated_expr.clone()
                }),
                data_type: datafusion::arrow::datatypes::DataType::Int32,
            });
            Expr::BinaryExpr(BinaryExpr {
                left: Box::new(lhs),
                op: Operator::Minus,
                right: Box::new(rhs),
            })
            .alias(name.to_string())
        } else {
            let raw_diff = if is_asc {
                Expr::BinaryExpr(BinaryExpr {
                    left: Box::new(rotated_expr.clone()),
                    op: Operator::Minus,
                    right: Box::new(col(name)),
                })
            } else {
                Expr::BinaryExpr(BinaryExpr {
                    left: Box::new(col(name)),
                    op: Operator::Minus,
                    right: Box::new(rotated_expr.clone()),
                })
            };
            Expr::Cast(Cast {
                expr: Box::new(raw_diff),
                data_type: field.data_type().clone(),
            })
            .alias(name.to_string())
        };
        diff_cols.push(diff_expr);
    }

    ordered.select(diff_cols)
}

/// Builds a boolean tie-indicator table:
/// `tie_k` is true on row i iff rows i and i+1 match on columns [0..k-1].
pub(crate) fn tie_indicator(
    df: DataFrame,
    order_by: Vec<SortExpr>,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let schema = df.schema();
    let has_row_id = schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let order_by = if !order_by.is_empty() {
        order_by
    } else if has_row_id {
        vec![col(ROW_ID_COL_NAME).sort(true, true)]
    } else {
        return Err(DataFusionError::Plan(
            "tie_indicator requires ordering or __row_id__ column".to_string(),
        ));
    };

    let mut data_cols: Vec<String> = schema
        .fields()
        .iter()
        .map(|field| field.name().to_string())
        // Tie indicators should only consider data columns (not activator/row_id).
        .filter(|name| !is_system_column(name))
        .collect();
    if !sort_specs.is_empty() {
        let mut ordered = Vec::with_capacity(data_cols.len());
        for (name, _, _) in sort_specs {
            let normalized = normalize_sort_name(name);
            if let Some(col_name) = data_cols
                .iter()
                .find(|col_name| normalize_sort_name(col_name) == normalized)
            {
                ordered.push(col_name.clone());
            }
        }
        if ordered.len() == data_cols.len() {
            data_cols = ordered;
        }
    }
    if data_cols.len() < 2 {
        return df.select(Vec::<Expr>::new());
    }

    let ordered = df.sort(order_by.clone())?;

    let mut prefix = lit(true);
    let mut out = Vec::with_capacity(data_cols.len() - 1);

    for (idx, col_name) in data_cols.iter().enumerate().take(data_cols.len() - 1) {
        let next_val = lead(col(col_name), Some(1), None)
            .order_by(order_by.clone())
            .build()?;
        // Treat NULL = NULL as equal for tie propagation.
        let eq = Expr::BinaryExpr(BinaryExpr {
            left: Box::new(col(col_name)),
            op: Operator::IsNotDistinctFrom,
            right: Box::new(next_val),
        });
        prefix = prefix.and(eq);
        out.push(prefix.clone().alias(format!("tie_{}", idx + 1)));
    }

    ordered.select(out)
}

fn sort_order_from_hint(
    hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) -> Vec<SortExpr> {
    let schema = hint.data_frame().schema();
    let mut order_by = Vec::new();

    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME)
    {
        order_by.push(col(ACTIVATOR_COL_NAME).sort(false, false));
    }

    let data_fields: Vec<_> = schema
        .fields()
        .iter()
        .filter(|field| !is_system_column(field.name()))
        .collect();
    if !sort_specs.is_empty() {
        let mut ordered = Vec::with_capacity(sort_specs.len());
        for (name, asc, nulls_first) in sort_specs {
            let normalized = normalize_sort_name(name);
            if let Some(field) = data_fields
                .iter()
                .find(|field| normalize_sort_name(field.name()) == normalized)
            {
                ordered.push(col(field.name()).sort(*asc, *nulls_first));
            }
        }
        if ordered.len() == data_fields.len() {
            order_by.extend(ordered);
        } else {
            order_by.extend(
                data_fields
                    .iter()
                    .map(|field| col(field.name()).sort(true, true)),
            );
        }
    } else {
        order_by.extend(
            data_fields
                .iter()
                .map(|field| col(field.name()).sort(true, true)),
        );
    }

    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        // Row-id is only a deterministic tiebreaker once the sort order is fixed.
        order_by.push(col(ROW_ID_COL_NAME).sort(true, true));
    }

    order_by
}

fn normalize_sort_name(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).to_string()
}

fn sort_is_asc(sort_specs: &[(String, bool, bool)], col_name: &str) -> bool {
    sort_specs
        .iter()
        .find(|(name, _, _)| normalize_sort_name(name) == normalize_sort_name(col_name))
        .map(|(_, asc, _)| *asc)
        .unwrap_or(true)
}
