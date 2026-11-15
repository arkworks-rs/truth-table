//! Narrows `x BETWEEN a AND b` with constant bounds: over at most
//! [`MAX_VALUES`] values it becomes `x IN (a, .., b)` (`NOT BETWEEN`,
//! `NOT IN`), and over more it is compared at `x`'s own type.
//!
//! A BETWEEN is otherwise proved as two comparisons, each a sign check over
//! the full width of its operands' type, whatever the interval.
//! `SimplifyExpressions` splits an IN list of up to three values into
//! equalities joined by OR (a NOT IN into inequalities joined by AND), and an
//! equality with a constant costs far less than a comparison. A longer list
//! goes to the membership gadget, a zerocheck whose degree grows with the
//! list and soon costs more than the two comparisons.
//!
//! Type coercion may also widen `x` to the bounds' type: a Decimal(15, 2)
//! column against a float literal becomes Decimal(30, 15), an Int32 against
//! an Int64 literal Int64, and the comparisons span that width. When the
//! widening keeps every value of `x`, the bounds are rounded inward to `x`'s
//! own type, where no value of `x` lies between a bound and its rounding,
//! and the cast is dropped.
//!
//! The rule runs after type coercion, so `x`, `a` and `b` share a type, and
//! before `SimplifyExpressions`, which turns every BETWEEN into comparisons.
//! Integer, decimal and date bounds are rewritten: the values between them
//! are the integers that encode them.

use datafusion::{
    arrow::datatypes::DataType, config::ConfigOptions, optimizer::analyzer::AnalyzerRule,
};
use datafusion_common::{
    DFSchema, Result, ScalarValue,
    tree_node::{Transformed, TreeNode},
};
use datafusion_expr::{
    Expr, ExprSchemable,
    expr::{Between, Cast, InList},
    expr_rewriter::NamePreserver,
    logical_plan::LogicalPlan,
    utils::merge_schema,
};

/// The most values a BETWEEN is rewritten for.
const MAX_VALUES: i128 = 3;

#[derive(Debug, Default)]
pub(crate) struct NarrowBetween;

impl NarrowBetween {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl AnalyzerRule for NarrowBetween {
    fn name(&self) -> &str {
        "narrow_between"
    }

    fn analyze(&self, plan: LogicalPlan, _config: &ConfigOptions) -> Result<LogicalPlan> {
        plan.transform_up_with_subqueries(rewrite_plan)
            .map(|res| res.data)
    }
}

fn rewrite_plan(plan: LogicalPlan) -> Result<Transformed<LogicalPlan>> {
    let schema = merge_schema(&plan.inputs());
    let name_preserver = NamePreserver::new(&plan);
    plan.map_expressions(|expr| {
        let name = name_preserver.save(&expr);
        expr.transform_up(|expr| match expr {
            Expr::Between(between) => rewrite_between(between, &schema),
            other => Ok(Transformed::no(other)),
        })
        .map(|res| res.update_data(|expr| name.restore(expr)))
    })
}

fn rewrite_between(between: Between, schema: &DFSchema) -> Result<Transformed<Expr>> {
    let outer_type = between.expr.get_type(schema)?;
    // Type coercion may widen `x` to the bounds' type, e.g. a Decimal(15, 2)
    // column against a float literal to Decimal(30, 15). An exact widening
    // keeps the values of `x`, so the list is built on `x` itself at its
    // own scale.
    let (inner, shift) = match between.expr.as_ref() {
        Expr::Cast(Cast { expr, data_type }) => {
            match exact_scale_shift(&expr.get_type(schema)?, data_type) {
                Some(shift) => (expr.as_ref().clone(), shift),
                None => (between.expr.as_ref().clone(), 0),
            }
        }
        other => (other.clone(), 0),
    };
    let inner_type = inner.get_type(schema)?;
    let bound = |expr: &Expr| {
        constant(expr)
            .and_then(|value| value.cast_to(&outer_type).ok())
            .and_then(|value| encoding(&value))
    };
    let (Some(low), Some(high)) = (bound(&between.low), bound(&between.high)) else {
        return Ok(Transformed::no(Expr::Between(between)));
    };
    let Some((low, high)) = rounded_inward(low, high, shift) else {
        return Ok(Transformed::no(Expr::Between(between)));
    };
    if high - low < MAX_VALUES {
        let list = (low..=high)
            .map(|value| from_encoding(value, &inner_type).map(Expr::Literal))
            .collect::<Option<Vec<_>>>();
        if let Some(list) = list {
            return Ok(Transformed::yes(Expr::InList(InList {
                expr: Box::new(inner),
                list,
                negated: between.negated,
            })));
        }
    }
    // A longer interval stays two comparisons, at `x`'s own width when the
    // widening could be dropped.
    match (
        &inner != between.expr.as_ref(),
        from_encoding(low, &inner_type),
        from_encoding(high, &inner_type),
    ) {
        (true, Some(low), Some(high)) => Ok(Transformed::yes(Expr::Between(Between::new(
            Box::new(inner),
            between.negated,
            Box::new(Expr::Literal(low)),
            Box::new(Expr::Literal(high)),
        )))),
        _ => Ok(Transformed::no(Expr::Between(between))),
    }
}

/// The value of a literal, through the casts type coercion adds.
fn constant(expr: &Expr) -> Option<ScalarValue> {
    match expr {
        Expr::Literal(value) => Some(value.clone()),
        Expr::Cast(Cast { expr, data_type }) => constant(expr)?.cast_to(data_type).ok(),
        _ => None,
    }
}

/// `k` when every value of `from` is the value of `to` whose encoding is
/// `10^k` times its own; `None` for a cast that can change a value.
fn exact_scale_shift(from: &DataType, to: &DataType) -> Option<u32> {
    let shape = |data_type: &DataType| -> Option<(i32, i32)> {
        match data_type {
            DataType::Decimal128(precision, scale) => {
                Some((i32::from(*precision) - i32::from(*scale), (*scale).into()))
            }
            DataType::Int8 | DataType::UInt8 => Some((3, 0)),
            DataType::Int16 | DataType::UInt16 => Some((5, 0)),
            DataType::Int32 | DataType::UInt32 => Some((10, 0)),
            DataType::Int64 => Some((19, 0)),
            DataType::UInt64 => Some((20, 0)),
            _ => None,
        }
    };
    let ((from_digits, from_scale), (to_digits, to_scale)) = (shape(from)?, shape(to)?);
    (to_scale >= from_scale && to_digits >= from_digits).then(|| (to_scale - from_scale) as u32)
}

/// The bounds of an interval of encodings of a type `10^shift` times finer,
/// as encodings of `x`'s own type, rounded inward: no value of that type lies
/// between a bound and its rounding. `None` for an empty interval.
fn rounded_inward(low: i128, high: i128, shift: u32) -> Option<(i128, i128)> {
    let unit = 10i128.checked_pow(shift)?;
    let low = -(-low).div_euclid(unit);
    let high = high.div_euclid(unit);
    (low <= high).then_some((low, high))
}

/// The integer a value is proved as.
fn encoding(value: &ScalarValue) -> Option<i128> {
    Some(match value {
        ScalarValue::Int8(Some(v)) => (*v).into(),
        ScalarValue::Int16(Some(v)) => (*v).into(),
        ScalarValue::Int32(Some(v)) | ScalarValue::Date32(Some(v)) => (*v).into(),
        ScalarValue::Int64(Some(v)) => (*v).into(),
        ScalarValue::UInt8(Some(v)) => (*v).into(),
        ScalarValue::UInt16(Some(v)) => (*v).into(),
        ScalarValue::UInt32(Some(v)) => (*v).into(),
        ScalarValue::UInt64(Some(v)) => (*v).into(),
        ScalarValue::Decimal128(Some(v), ..) => *v,
        _ => return None,
    })
}

/// The literal of `data_type` encoded as `value`, if the type holds it.
fn from_encoding(value: i128, data_type: &DataType) -> Option<ScalarValue> {
    match data_type {
        DataType::Decimal128(precision, scale) => (value.unsigned_abs()
            < 10u128.pow((*precision).into()))
        .then_some(ScalarValue::Decimal128(Some(value), *precision, *scale)),
        DataType::Date32 => Some(ScalarValue::Date32(Some(value.try_into().ok()?))),
        other if other.is_integer() => ScalarValue::Int64(Some(value.try_into().ok()?))
            .cast_to(other)
            .ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::datatypes::{Field, Schema};
    use datafusion_expr::{col, lit, logical_plan::builder::table_scan};

    use super::*;

    fn rewritten(predicate: Expr, data_type: DataType) -> Expr {
        let schema = Schema::new(vec![Field::new("x", data_type, false)]);
        let plan = table_scan(Some("t"), &schema, None)
            .unwrap()
            .filter(predicate)
            .unwrap()
            .build()
            .unwrap();
        let plan = rewrite_plan(plan).unwrap().data;
        let LogicalPlan::Filter(filter) = plan else {
            panic!("expected a filter");
        };
        filter.predicate
    }

    fn decimal(v: i128) -> Expr {
        lit(ScalarValue::Decimal128(Some(v), 15, 2))
    }

    #[test]
    fn a_short_interval_becomes_an_in_list() {
        let predicate = rewritten(
            col("t.x").between(decimal(5), decimal(7)),
            DataType::Decimal128(15, 2),
        );
        assert_eq!(
            predicate,
            col("t.x").in_list(vec![decimal(5), decimal(6), decimal(7)], false)
        );
        let predicate = rewritten(
            col("t.x").not_between(lit(4i64), lit(4i64)),
            DataType::Int64,
        );
        assert_eq!(predicate, col("t.x").in_list(vec![lit(4i64)], true));
    }

    #[test]
    fn a_longer_or_empty_interval_stays() {
        for (low, high) in [(1i64, 4i64), (5, 4)] {
            let between = col("t.x").between(lit(low), lit(high));
            assert_eq!(rewritten(between.clone(), DataType::Int64), between);
        }
    }

    #[test]
    fn bounds_that_are_not_constant_stay() {
        let between = col("t.x").between(col("t.x"), lit(2i64));
        assert_eq!(rewritten(between.clone(), DataType::Int64), between);
    }

    /// Type coercion lifts a Decimal(15, 2) column against float bounds to
    /// Decimal(30, 15); the list, or the comparisons, are on the column at
    /// scale 2, with the bounds rounded inward.
    #[test]
    fn a_widened_column_is_narrowed_to_its_own_scale() {
        let widened = |low: f64, high: f64| {
            let to = DataType::Decimal128(30, 15);
            Expr::Cast(Cast::new(Box::new(col("t.x")), to.clone())).between(
                Expr::Cast(Cast::new(Box::new(lit(low)), to.clone())),
                Expr::Cast(Cast::new(Box::new(lit(high)), to)),
            )
        };
        let column = DataType::Decimal128(15, 2);
        assert_eq!(
            rewritten(widened(0.05, 0.07), column.clone()),
            col("t.x").in_list(vec![decimal(5), decimal(6), decimal(7)], false)
        );
        assert_eq!(
            rewritten(widened(0.051, 0.07), column.clone()),
            col("t.x").in_list(vec![decimal(6), decimal(7)], false)
        );
        assert_eq!(
            rewritten(widened(0.05, 0.09), column),
            col("t.x").between(decimal(5), decimal(9))
        );
    }

    #[test]
    fn dates_are_rewritten_by_day() {
        let day = |d: i32| lit(ScalarValue::Date32(Some(d)));
        let predicate = rewritten(col("t.x").between(day(9000), day(9001)), DataType::Date32);
        assert_eq!(
            predicate,
            col("t.x").in_list(vec![day(9000), day(9001)], false)
        );
    }
}
