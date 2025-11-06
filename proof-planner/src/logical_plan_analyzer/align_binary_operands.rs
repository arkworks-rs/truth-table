use std::sync::Arc;

use super::common::cast_expression_to_type;
use datafusion::{
    arrow::datatypes::DataType, config::ConfigOptions, optimizer::analyzer::AnalyzerRule,
};
use datafusion_common::{
    tree_node::{Transformed, TreeNode},
    DFSchema, Result,
};
use datafusion_expr::{
    expr::{BinaryExpr, Exists, InSubquery},
    logical_plan::{LogicalPlan, Subquery},
    utils::merge_schema,
    Expr, ExprSchemable, Operator,
};

#[derive(Debug, Default)]
pub(crate) struct AlignBinaryOperands;

impl AlignBinaryOperands {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl AnalyzerRule for AlignBinaryOperands {
    fn name(&self) -> &str {
        "align_binary_operands"
    }

    fn analyze(&self, plan: LogicalPlan, _config: &ConfigOptions) -> Result<LogicalPlan> {
        let empty_schema = DFSchema::empty();
        plan.transform_up_with_subqueries(|plan| align_plan(&empty_schema, plan))
            .map(|res| res.data)
    }
}

fn align_plan(external_schema: &DFSchema, plan: LogicalPlan) -> Result<Transformed<LogicalPlan>> {
    let mut schema = merge_schema(&plan.inputs());

    if let LogicalPlan::TableScan(scan) = &plan {
        let source_schema =
            DFSchema::try_from_qualified_schema(scan.table_name.clone(), &scan.source.schema())?;
        schema.merge(&source_schema);
    }

    schema.merge(external_schema);

    plan.map_expressions(|expr| {
        let mut rewriter = AlignBinaryOperandsRewriter::new(&schema);
        expr.rewrite(&mut rewriter)
    })
}

struct AlignBinaryOperandsRewriter<'a> {
    schema: &'a DFSchema,
}

impl<'a> AlignBinaryOperandsRewriter<'a> {
    fn new(schema: &'a DFSchema) -> Self {
        Self { schema }
    }
}

impl<'a> datafusion_common::tree_node::TreeNodeRewriter for AlignBinaryOperandsRewriter<'a> {
    type Node = Expr;

    fn f_up(&mut self, expr: Expr) -> Result<Transformed<Expr>> {
        match expr {
            Expr::ScalarSubquery(Subquery {
                subquery,
                outer_ref_columns,
            }) => {
                let new_plan = align_plan(self.schema, Arc::unwrap_or_clone(subquery))?.data;
                Ok(Transformed::yes(Expr::ScalarSubquery(Subquery {
                    subquery: Arc::new(new_plan),
                    outer_ref_columns,
                })))
            },
            Expr::Exists(Exists { subquery, negated }) => {
                let new_plan =
                    align_plan(self.schema, Arc::unwrap_or_clone(subquery.subquery.clone()))?.data;
                Ok(Transformed::yes(Expr::Exists(Exists {
                    subquery: Subquery {
                        subquery: Arc::new(new_plan),
                        outer_ref_columns: subquery.outer_ref_columns,
                    },
                    negated,
                })))
            },
            Expr::InSubquery(InSubquery {
                expr: input_expr,
                subquery,
                negated,
            }) => {
                let new_plan =
                    align_plan(self.schema, Arc::unwrap_or_clone(subquery.subquery.clone()))?.data;
                Ok(Transformed::yes(Expr::InSubquery(InSubquery::new(
                    input_expr,
                    Subquery {
                        subquery: Arc::new(new_plan),
                        outer_ref_columns: subquery.outer_ref_columns,
                    },
                    negated,
                ))))
            },
            Expr::BinaryExpr(binary) => align_binary_expr(binary, self.schema),
            _ => Ok(Transformed::no(expr)),
        }
    }
}

fn align_binary_expr(mut binary: BinaryExpr, schema: &DFSchema) -> Result<Transformed<Expr>> {
    if !matches!(
        binary.op,
        Operator::Plus | Operator::Minus | Operator::Multiply | Operator::Divide | Operator::Modulo
    ) {
        return Ok(Transformed::no(Expr::BinaryExpr(binary)));
    }

    let left_type = binary.left.get_type(schema)?;
    let right_type = binary.right.get_type(schema)?;

    if !is_decimal_type(&left_type) && !is_decimal_type(&right_type) {
        return Ok(Transformed::no(Expr::BinaryExpr(binary)));
    }

    let left_column_decimal = extract_decimal_column_type(binary.left.as_ref(), schema);
    let right_column_decimal = extract_decimal_column_type(binary.right.as_ref(), schema);

    let mut changed = false;

    match (left_column_decimal, right_column_decimal) {
        (Some(target_type), None) => {
            changed |= align_operand(&mut binary.left, &target_type, schema)?;
            changed |= align_operand(&mut binary.right, &target_type, schema)?;
        },
        (None, Some(target_type)) => {
            changed |= align_operand(&mut binary.left, &target_type, schema)?;
            changed |= align_operand(&mut binary.right, &target_type, schema)?;
        },
        (Some(_), Some(_)) | (None, None) => {
            return Ok(Transformed::no(Expr::BinaryExpr(binary)));
        },
    }

    if changed {
        Ok(Transformed::yes(Expr::BinaryExpr(binary)))
    } else {
        Ok(Transformed::no(Expr::BinaryExpr(binary)))
    }
}

fn align_operand(expr: &mut Box<Expr>, target_type: &DataType, schema: &DFSchema) -> Result<bool> {
    let new_expr = cast_expression_to_type((**expr).clone(), target_type, schema)?;
    if new_expr != **expr {
        *expr = Box::new(new_expr);
        Ok(true)
    } else {
        Ok(false)
    }
}

fn is_decimal_type(data_type: &DataType) -> bool {
    matches!(
        data_type,
        DataType::Decimal128(_, _) | DataType::Decimal256(_, _)
    )
}

fn extract_decimal_column_type(expr: &Expr, schema: &DFSchema) -> Option<DataType> {
    match expr {
        Expr::Column(col) => {
            schema
                .field_from_column(col)
                .ok()
                .and_then(|field| match field.data_type() {
                    DataType::Decimal128(..) | DataType::Decimal256(..) => {
                        Some(field.data_type().clone())
                    },
                    _ => None,
                })
        },
        Expr::Cast(cast) => extract_decimal_column_type(&cast.expr, schema),
        Expr::TryCast(cast) => extract_decimal_column_type(&cast.expr, schema),
        Expr::Alias(alias) => extract_decimal_column_type(&alias.expr, schema),
        Expr::OuterReferenceColumn(data_type, _) if is_decimal_type(data_type) => {
            Some(data_type.clone())
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_common::{Result, ScalarValue};
    use datafusion_expr::{
        expr::Cast,
        expr_fn::{binary_expr, col},
        logical_plan::builder::table_scan,
        Expr, LogicalPlan, Operator,
    };

    use crate::logical_plan_analyzer::{analyze_logical_plan, logical_plan_analyzer_rules};

    fn projection_expr(plan: &LogicalPlan) -> &Expr {
        match plan {
            LogicalPlan::Projection(projection) => projection
                .expr
                .first()
                .expect("projection expression should exist"),
            other => panic!("unexpected plan variant {other:?}"),
        }
    }

    #[test]
    fn aligns_literal_with_decimal_column() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Decimal128(10, 2), true)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .project(vec![binary_expr(
                col("a"),
                Operator::Plus,
                Expr::Literal(ScalarValue::Int64(Some(1))),
            )])?
            .build()?;

        let analyzed = analyze_logical_plan(plan, logical_plan_analyzer_rules());
        let expr = projection_expr(&analyzed);
        let Expr::BinaryExpr(binary) = expr else {
            panic!("expected binary expr, found {expr:?}");
        };

        match binary.right.as_ref() {
            Expr::Cast(Cast { data_type, .. }) => match data_type {
                DataType::Decimal128(_, scale) | DataType::Decimal256(_, scale) => {
                    assert_eq!(*scale, 2);
                },
                other => panic!("expected decimal cast, found {other:?}"),
            },
            other => panic!("expected cast on right operand, found {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn aligns_decimal_when_column_on_right() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Decimal128(6, 3), false)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .project(vec![binary_expr(
                Expr::Literal(ScalarValue::Int32(Some(10))),
                Operator::Multiply,
                col("a"),
            )])?
            .build()?;

        let analyzed = analyze_logical_plan(plan, logical_plan_analyzer_rules());
        let expr = projection_expr(&analyzed);
        let Expr::BinaryExpr(binary) = expr else {
            panic!("expected binary expr");
        };

        match binary.left.as_ref() {
            Expr::Cast(Cast { data_type, .. }) => match data_type {
                DataType::Decimal128(_, scale) | DataType::Decimal256(_, scale) => {
                    assert_eq!(*scale, 3);
                },
                other => panic!("expected decimal cast, found {other:?}"),
            },
            other => panic!("expected cast on left operand, found {other:?}"),
        }

        Ok(())
    }
}
