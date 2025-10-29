use datafusion::arrow::datatypes::DataType;
use datafusion_common::{DFSchema, Result};
use datafusion_expr::{Expr, ExprSchemable};

/// Casts `expr` to `target_type`, reusing existing casts when possible.
pub(super) fn cast_expression_to_type(
    expr: Expr,
    target_type: &DataType,
    schema: &DFSchema,
) -> Result<Expr> {
    if expr.get_type(schema)? == *target_type {
        return Ok(expr);
    }

    match expr {
        Expr::Cast(mut cast) => {
            cast.data_type = target_type.clone();
            Ok(Expr::Cast(cast))
        },
        other => other.cast_to(target_type, schema),
    }
}
