use crate::irs::nodes::gadget::utils::sort::{ROTATED_INPUT_LABEL, TIE_INDICATOR_LABEL};
use arithmetic::{ROW_ID_COL_NAME, is_system_column};
use datafusion::logical_expr::Expr;
use datafusion::logical_expr::col;
use datafusion::logical_expr::lit;
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::ExprFunctionExt;
use datafusion_expr::SortExpr;
use datafusion_expr::when;

use datafusion::functions_window::expr_fn::{first_value, lead};
use indexmap::IndexMap;
pub(crate) fn populate_rotated(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
) {
    let rotated_df =
        rotate(input_hint.data_frame().clone()).expect("sort rotate planning should succeed");
    let should_materialize = rotated_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), !is_system_column(field.name())))
        .collect();
    let rotated_hint = crate::irs::nodes::hints::HintDF::new(rotated_df, should_materialize);
    gadget_payload.insert(ROTATED_INPUT_LABEL.to_string(), rotated_hint);
}

pub(crate) fn populate_tie_indicator(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
) {
    let tie_df = tie_indicator(input_hint.data_frame().clone(), Vec::new())
        .expect("sort tie indicator planning should succeed");
    let should_materialize = tie_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), !is_system_column(field.name())))
        .collect();
    let tie_hint = crate::irs::nodes::hints::HintDF::new(tie_df, should_materialize);
    gadget_payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_hint);
}

pub(crate) fn rotate(df: DataFrame) -> DataFusionResult<DataFrame> {
    let has_row_id = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    if !has_row_id {
        return Err(DataFusionError::Plan(format!(
            "rotate requires {} column for deterministic ordering",
            ROW_ID_COL_NAME
        )));
    }

    let ordered = df.sort(vec![col(ROW_ID_COL_NAME).sort(true, true)])?;
    let mut rotated_cols = Vec::new();
    let order_by = vec![col(ROW_ID_COL_NAME).sort(true, true)];

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

/// Builds a boolean tie-indicator table:
/// `tie_k` is true on row i iff rows i and i+1 match on columns [0..k-1].
pub(crate) fn tie_indicator(df: DataFrame, order_by: Vec<SortExpr>) -> DataFusionResult<DataFrame> {
    let schema = df.schema();
    let has_row_id = schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let order_by = if has_row_id {
        vec![col(ROW_ID_COL_NAME).sort(true, true)]
    } else {
        order_by
    };
    if order_by.is_empty() {
        return Err(DataFusionError::Plan(
            "tie_indicator requires ordering or __row_id__ column".to_string(),
        ));
    }

    let data_cols: Vec<String> = schema
        .fields()
        .iter()
        .map(|field| field.name().to_string())
        .filter(|name| name != ROW_ID_COL_NAME)
        .collect();
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
        let eq = col(col_name).eq(next_val);
        let eq_non_null = when(eq.clone().is_null(), lit(false)).otherwise(eq)?;
        prefix = prefix.and(eq_non_null);
        out.push(prefix.clone().alias(format!("tie_{}", idx + 1)));
    }

    ordered.select(out)
}
